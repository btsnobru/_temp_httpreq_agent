
import re
import hashlib
from typing import Dict, List, Any, Optional
import logging

class FingerprintAnalyzer:
    """
    Advanced fingerprinting analyzer for HTTP infrastructure identification.
    
    Specialized in detecting technologies relevant to HTTP Request Smuggling:
    - Web servers with known parsing discrepancies
    - CDN providers with bypass potential
    - Load balancers and proxy configurations
    - WAF solutions and their characteristics
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._load_signatures()
    
    def _load_signatures(self):
        """Load technology signatures and patterns."""
        
        # Web server signatures
        self.web_server_signatures = {
            'nginx': {
                'headers': ['nginx'],
                'patterns': [
                    r'nginx/[\d\.]+',
                    r'server:\s*nginx',
                ],
                'desync_relevance': 'high',  # Known for parsing discrepancies
                'common_versions': ['1.18', '1.20', '1.22', '1.24']
            },
            'apache': {
                'headers': ['apache'],
                'patterns': [
                    r'apache/[\d\.]+',
                    r'server:\s*apache',
                ],
                'desync_relevance': 'medium',
                'common_versions': ['2.4.41', '2.4.48', '2.4.52']
            },
            'iis': {
                'headers': ['microsoft-iis', 'iis'],
                'patterns': [
                    r'microsoft-iis/[\d\.]+',
                    r'server:\s*microsoft-iis',
                ],
                'desync_relevance': 'medium',
                'common_versions': ['10.0', '8.5', '7.5']
            },
            'cloudflare': {
                'headers': ['cloudflare'],
                'patterns': [
                    r'server:\s*cloudflare',
                    r'cf-ray:\s*[\w\-]+',
                ],
                'desync_relevance': 'high',  # Known bypass techniques
                'bypass_methods': ['expect_obfuscated', 'double_desync']
            },
            'lighttpd': {
                'headers': ['lighttpd'],
                'patterns': [
                    r'lighttpd/[\d\.]+',
                ],
                'desync_relevance': 'low'
            },
            'caddy': {
                'headers': ['caddy'],
                'patterns': [
                    r'server:\s*caddy',
                ],
                'desync_relevance': 'low'
            }
        }
        
        # CDN provider signatures
        self.cdn_signatures = {
            'cloudflare': {
                'headers': ['cf-ray', 'cf-cache-status', 'cf-request-id'],
                'patterns': [
                    r'cf-ray:\s*[\w\-]+',
                    r'server:\s*cloudflare',
                ],
                'desync_potential': 'high',
                'known_bypasses': ['expect_obfuscated', 'vh_discrepancy']
            },
            'akamai': {
                'headers': ['akamai-ghost', 'x-akamai-config-log-detail'],
                'patterns': [
                    r'akamai',
                    r'x-cache.*akamai',
                ],
                'desync_potential': 'medium',
                'known_bypasses': ['zero_cl', 'header_masquerading']
            },
            'fastly': {
                'headers': ['x-served-by', 'x-cache', 'x-timer'],
                'patterns': [
                    r'x-served-by:\s*cache-[\w\-]+',
                    r'fastly',
                ],
                'desync_potential': 'medium'
            },
            'aws_cloudfront': {
                'headers': ['x-amz-cf-id', 'x-amz-cf-pop'],
                'patterns': [
                    r'x-amz-cf-id:\s*[\w\-]+',
                    r'cloudfront',
                ],
                'desync_potential': 'low'
            }
        }
        
        # WAF signatures
        self.waf_signatures = {
            'cloudflare_waf': {
                'headers': ['cf-ray'],
                'patterns': [
                    r'cloudflare',
                    r'cf-ray',
                ],
                'bypass_difficulty': 'medium',
                'known_bypasses': ['expect_obfuscation', 'case_variation']
            },
            'akamai_kona': {
                'headers': ['akamai'],
                'patterns': [
                    r'reference #[\w\.]+',
                    r'akamai',
                ],
                'bypass_difficulty': 'high'
            },
            'incapsula': {
                'headers': ['incap_ses', 'visid_incap'],
                'patterns': [
                    r'incapsula',
                    r'incap_ses',
                ],
                'bypass_difficulty': 'medium'
            },
            'sucuri': {
                'headers': ['x-sucuri-id'],
                'patterns': [
                    r'sucuri',
                    r'x-sucuri',
                ],
                'bypass_difficulty': 'low'
            },
            'wordfence': {
                'patterns': [
                    r'wordfence',
                    r'this response was generated by wordfence',
                ],
                'bypass_difficulty': 'low'
            }
        }
    
    def analyze_infrastructure(self, response_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive infrastructure analysis for desync attack planning.
        
        Args:
            response_data: HTTP response data including headers, content, etc.
            
        Returns:
            Detailed infrastructure fingerprint with desync relevance
        """
        headers = response_data.get('headers', {})
        content = response_data.get('content', '')
        
        analysis = {
            'web_servers': self._detect_web_servers(headers, content),
            'cdn_providers': self._detect_cdn_providers(headers),
            'waf_solutions': self._detect_waf_solutions(headers, content),
            'load_balancers': self._detect_load_balancers(headers),
            'backend_technologies': self._detect_backend_tech(headers),
            'desync_assessment': {},
            'recommended_techniques': [],
            'bypass_strategies': []
        }
        
        # Generate desync assessment
        analysis['desync_assessment'] = self._assess_desync_potential(analysis)
        
        # Recommend techniques
        analysis['recommended_techniques'] = self._recommend_techniques(analysis)
        
        # Suggest bypass strategies
        analysis['bypass_strategies'] = self._suggest_bypass_strategies(analysis)
        
        return analysis
    
    def _detect_web_servers(self, headers: Dict[str, str], content: str) -> List[Dict[str, Any]]:
        """Detect web server technologies."""
        detected = []
        headers_text = self._headers_to_text(headers).lower()
        content_lower = content.lower()
        
        for server, signature in self.web_server_signatures.items():
            confidence = 0.0
            evidence = []
            
            # Check header patterns
            for pattern in signature['patterns']:
                if re.search(pattern, headers_text, re.IGNORECASE):
                    confidence += 0.6
                    evidence.append(f"Header pattern: {pattern}")
            
            # Check specific headers
            for header in signature['headers']:
                if header in headers_text:
                    confidence += 0.4
                    evidence.append(f"Header indicator: {header}")
            
            # Version detection
            version = self._extract_version(headers_text, server)
            
            if confidence > 0.3:
                detected.append({
                    'server': server,
                    'confidence': min(confidence, 1.0),
                    'evidence': evidence,
                    'version': version,
                    'desync_relevance': signature.get('desync_relevance', 'low'),
                    'known_versions': signature.get('common_versions', []),
                    'bypass_methods': signature.get('bypass_methods', [])
                })
        
        return sorted(detected, key=lambda x: x['confidence'], reverse=True)
    
    def _detect_cdn_providers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Detect CDN providers."""
        detected = []
        headers_text = self._headers_to_text(headers).lower()
        
        for cdn, signature in self.cdn_signatures.items():
            confidence = 0.0
            evidence = []
            
            # Check specific headers
            for header in signature['headers']:
                if header.lower() in headers_text:
                    confidence += 0.7
                    evidence.append(f"CDN header: {header}")
            
            # Check patterns
            for pattern in signature['patterns']:
                if re.search(pattern, headers_text, re.IGNORECASE):
                    confidence += 0.5
                    evidence.append(f"CDN pattern: {pattern}")
            
            if confidence > 0.4:
                detected.append({
                    'cdn': cdn,
                    'confidence': min(confidence, 1.0),
                    'evidence': evidence,
                    'desync_potential': signature.get('desync_potential', 'low'),
                    'known_bypasses': signature.get('known_bypasses', [])
                })
        
        return sorted(detected, key=lambda x: x['confidence'], reverse=True)
    
    def _detect_waf_solutions(self, headers: Dict[str, str], content: str) -> List[Dict[str, Any]]:
        """Detect WAF solutions."""
        detected = []
        headers_text = self._headers_to_text(headers).lower()
        content_lower = content.lower()
        
        for waf, signature in self.waf_signatures.items():
            confidence = 0.0
            evidence = []
            
            # Check headers
            for header in signature.get('headers', []):
                if header.lower() in headers_text:
                    confidence += 0.8
                    evidence.append(f"WAF header: {header}")
            
            # Check patterns in headers and content
            for pattern in signature['patterns']:
                if re.search(pattern, headers_text, re.IGNORECASE):
                    confidence += 0.6
                    evidence.append(f"WAF pattern in headers: {pattern}")
                elif re.search(pattern, content_lower, re.IGNORECASE):
                    confidence += 0.4
                    evidence.append(f"WAF pattern in content: {pattern}")
            
            if confidence > 0.3:
                detected.append({
                    'waf': waf,
                    'confidence': min(confidence, 1.0),
                    'evidence': evidence,
                    'bypass_difficulty': signature.get('bypass_difficulty', 'unknown'),
                    'known_bypasses': signature.get('known_bypasses', [])
                })
        
        return sorted(detected, key=lambda x: x['confidence'], reverse=True)
    
    def _detect_load_balancers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Detect load balancer technologies."""
        detected = []
        headers_text = self._headers_to_text(headers).lower()
        
        lb_indicators = {
            'f5_bigip': ['f5-', 'bigip', 'x-forwarded-server'],
            'nginx_lb': ['nginx', 'x-upstream'],
            'haproxy': ['haproxy', 'x-haproxy'],
            'aws_elb': ['awselb', 'x-amzn-requestid'],
            'google_lb': ['gfe', 'alt-svc.*gws'],
            'generic': ['x-forwarded-for', 'x-real-ip', 'via']
        }
        
        for lb, indicators in lb_indicators.items():
            confidence = 0.0
            evidence = []
            
            for indicator in indicators:
                if re.search(indicator, headers_text, re.IGNORECASE):
                    confidence += 0.3
                    evidence.append(f"LB indicator: {indicator}")
            
            if confidence > 0.2:
                detected.append({
                    'load_balancer': lb,
                    'confidence': min(confidence, 1.0),
                    'evidence': evidence
                })
        
        return sorted(detected, key=lambda x: x['confidence'], reverse=True)
    
    def _detect_backend_tech(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Detect backend technologies."""
        detected = []
        
        tech_indicators = {
            'php': {
                'headers': ['x-powered-by'],
                'patterns': [r'php/[\d\.]+', r'x-powered-by.*php']
            },
            'asp.net': {
                'headers': ['x-aspnet-version', 'x-powered-by'],
                'patterns': [r'asp\.net', r'x-aspnet-version']
            },
            'nodejs': {
                'headers': ['x-powered-by'],
                'patterns': [r'express', r'node\.js']
            },
            'java': {
                'headers': ['server'],
                'patterns': [r'tomcat', r'jetty', r'jboss']
            },
            'python': {
                'headers': ['server'],
                'patterns': [r'django', r'flask', r'gunicorn']
            }
        }
        
        headers_text = self._headers_to_text(headers).lower()
        
        for tech, signature in tech_indicators.items():
            confidence = 0.0
            evidence = []
            
            for pattern in signature['patterns']:
                if re.search(pattern, headers_text, re.IGNORECASE):
                    confidence += 0.6
                    evidence.append(f"Tech pattern: {pattern}")
            
            if confidence > 0.3:
                detected.append({
                    'technology': tech,
                    'confidence': min(confidence, 1.0),
                    'evidence': evidence
                })
        
        return sorted(detected, key=lambda x: x['confidence'], reverse=True)
    
    def _assess_desync_potential(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall desync attack potential."""
        
        # Base score
        base_score = 0.3
        
        # Web server contribution
        for server in analysis['web_servers']:
            if server['desync_relevance'] == 'high':
                base_score += 0.3
            elif server['desync_relevance'] == 'medium':
                base_score += 0.2
        
        # CDN contribution
        for cdn in analysis['cdn_providers']:
            if cdn['desync_potential'] == 'high':
                base_score += 0.2
            elif cdn['desync_potential'] == 'medium':
                base_score += 0.1
        
        # WAF impact (reduces potential)
        for waf in analysis['waf_solutions']:
            if waf['bypass_difficulty'] == 'high':
                base_score -= 0.2
            elif waf['bypass_difficulty'] == 'medium':
                base_score -= 0.1
        
        # Load balancer impact (increases potential)
        if analysis['load_balancers']:
            base_score += 0.1
        
        overall_score = max(0.0, min(base_score, 1.0))
        
        # Categorize potential
        if overall_score >= 0.7:
            potential_level = 'high'
        elif overall_score >= 0.5:
            potential_level = 'medium'
        else:
            potential_level = 'low'
        
        return {
            'overall_score': overall_score,
            'potential_level': potential_level,
            'contributing_factors': self._identify_contributing_factors(analysis),
            'limiting_factors': self._identify_limiting_factors(analysis)
        }
    
    def _recommend_techniques(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Recommend specific desync techniques based on infrastructure."""
        recommendations = []
        
        # Get dominant technologies
        primary_server = analysis['web_servers'][0] if analysis['web_servers'] else None
        primary_cdn = analysis['cdn_providers'][0] if analysis['cdn_providers'] else None
        primary_waf = analysis['waf_solutions'][0] if analysis['waf_solutions'] else None
        
        # Nginx-specific recommendations
        if primary_server and primary_server['server'] == 'nginx':
            recommendations.append({
                'technique': '0_cl_desync',
                'priority': 'high',
                'reason': 'Nginx vulnerable to 0.CL desync attacks',
                'success_probability': 0.8
            })
            
            recommendations.append({
                'technique': 'expect_obfuscated',
                'priority': 'medium',
                'reason': 'Nginx has Expect header parsing issues',
                'success_probability': 0.6
            })
        
        # Apache-specific recommendations
        elif primary_server and primary_server['server'] == 'apache':
            recommendations.append({
                'technique': 'vh_hv_discrepancy',
                'priority': 'high',
                'reason': 'Apache header parsing discrepancies',
                'success_probability': 0.7
            })
            
            recommendations.append({
                'technique': 'transfer_encoding',
                'priority': 'medium',
                'reason': 'Apache TE header handling issues',
                'success_probability': 0.5
            })
        
        # Cloudflare-specific recommendations
        if primary_cdn and primary_cdn['cdn'] == 'cloudflare':
            recommendations.append({
                'technique': 'expect_obfuscated',
                'priority': 'high',
                'reason': 'Known Cloudflare bypass technique',
                'success_probability': 0.9
            })
            
            recommendations.append({
                'technique': 'double_desync',
                'priority': 'medium',
                'reason': 'Cloudflare 0.CL -> CL.0 conversion',
                'success_probability': 0.6
            })
        
        # Generic recommendations
        if not recommendations:
            recommendations.extend([
                {
                    'technique': 'expect_vanilla',
                    'priority': 'medium',
                    'reason': 'Universal technique, works on most servers',
                    'success_probability': 0.4
                },
                {
                    'technique': 'vh_hv_discrepancy',
                    'priority': 'medium',
                    'reason': 'Header parsing differences common',
                    'success_probability': 0.5
                }
            ])
        
        return sorted(recommendations, key=lambda x: x['success_probability'], reverse=True)
    
    def _suggest_bypass_strategies(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Suggest WAF bypass strategies."""
        strategies = []
        
        for waf in analysis['waf_solutions']:
            waf_name = waf['waf']
            
            if 'cloudflare' in waf_name:
                strategies.append({
                    'target': 'Cloudflare WAF',
                    'strategy': 'expect_obfuscation',
                    'description': 'Use obfuscated Expect headers to bypass detection',
                    'payload_example': 'Expect: y 100-continue'
                })
                
                strategies.append({
                    'target': 'Cloudflare WAF',
                    'strategy': 'case_variation',
                    'description': 'Vary header case to confuse parser',
                    'payload_example': 'content-length: 0'
                })
            
            elif 'akamai' in waf_name:
                strategies.append({
                    'target': 'Akamai WAF',
                    'strategy': 'header_masquerading',
                    'description': 'Use leading spaces in critical headers',
                    'payload_example': ' Content-Length: 23'
                })
            
            else:
                strategies.append({
                    'target': f'{waf_name} WAF',
                    'strategy': 'generic_evasion',
                    'description': 'Use standard header obfuscation techniques',
                    'payload_example': 'Various header manipulation methods'
                })
        
        return strategies
    
    def _identify_contributing_factors(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify factors that increase desync potential."""
        factors = []
        
        for server in analysis['web_servers']:
            if server['desync_relevance'] == 'high':
                factors.append(f"High-risk web server: {server['server']}")
        
        for cdn in analysis['cdn_providers']:
            if cdn['desync_potential'] == 'high':
                factors.append(f"Vulnerable CDN: {cdn['cdn']}")
        
        if analysis['load_balancers']:
            factors.append("Load balancer presence increases complexity")
        
        return factors
    
    def _identify_limiting_factors(self, analysis: Dict[str, Any]) -> List[str]:
        """Identify factors that limit desync potential."""
        factors = []
        
        for waf in analysis['waf_solutions']:
            if waf['bypass_difficulty'] == 'high':
                factors.append(f"Strong WAF protection: {waf['waf']}")
            elif waf['bypass_difficulty'] == 'medium':
                factors.append(f"Moderate WAF protection: {waf['waf']}")
        
        return factors
    
    def _headers_to_text(self, headers: Dict[str, str]) -> str:
        """Convert headers dictionary to searchable text."""
        header_text = []
        for key, value in headers.items():
            header_text.append(f"{key.lower()}: {value.lower()}")
        return ' '.join(header_text)
    
    def _extract_version(self, headers_text: str, server_type: str) -> Optional[str]:
        """Extract version information for a server type."""
        patterns = {
            'nginx': r'nginx/([\d\.]+)',
            'apache': r'apache/([\d\.]+)',
            'iis': r'microsoft-iis/([\d\.]+)'
        }
        
        pattern = patterns.get(server_type)
        if pattern:
            match = re.search(pattern, headers_text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def generate_fingerprint_hash(self, analysis: Dict[str, Any]) -> str:
        """Generate a unique hash for the infrastructure fingerprint."""
        
        # Create a consistent string representation
        fingerprint_data = []
        
        for server in analysis.get('web_servers', []):
            fingerprint_data.append(f"server:{server['server']}:{server.get('version', 'unknown')}")
        
        for cdn in analysis.get('cdn_providers', []):
            fingerprint_data.append(f"cdn:{cdn['cdn']}")
        
        for waf in analysis.get('waf_solutions', []):
            fingerprint_data.append(f"waf:{waf['waf']}")
        
        fingerprint_string = '|'.join(sorted(fingerprint_data))
        
        # Generate SHA256 hash
        return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
