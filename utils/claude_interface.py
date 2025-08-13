
import asyncio
import logging
from typing import Dict, Any, List, Optional
import json
from anthropic import Anthropic

class ClaudeInterface:
    """
    Interface for interacting with Claude AI for intelligent vulnerability analysis.
    
    Provides specialized prompts and analysis methods for HTTP Request Smuggling
    detection, validation, and exploitation guidance.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.api_key = config['claude_api_key']
        self.model = config.get('model', 'claude-3-sonnet-20240229')
        self.max_tokens = config.get('max_tokens_per_request', 1000)
        self.logger = logging.getLogger(__name__)
        
        # Initialize Anthropic client
        self.client = Anthropic(api_key=self.api_key)
        
        # Token usage tracking
        self.total_tokens_used = 0
        self.requests_made = 0
    
    async def analyze(self, prompt: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Send analysis request to Claude and parse structured response.
        
        Args:
            prompt: Analysis prompt
            context: Additional context data
            
        Returns:
            Parsed analysis results
        """
        try:
            # Enhance prompt with context if provided
            if context:
                enhanced_prompt = f"{prompt}\n\nContext:\n{json.dumps(context, indent=2)}"
            else:
                enhanced_prompt = prompt
            
            # Make API request
            message = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                messages=[
                    {
                        "role": "user",
                        "content": enhanced_prompt
                    }
                ]
            )
            
            # Track usage
            self.requests_made += 1
            if hasattr(message, 'usage'):
                self.total_tokens_used += message.usage.input_tokens + message.usage.output_tokens
            
            # Parse response
            response_text = message.content[0].text if message.content else ""
            
            # Try to parse as JSON, fallback to text analysis
            try:
                parsed_response = self._parse_structured_response(response_text)
            except:
                parsed_response = {
                    'analysis': response_text,
                    'structured_data': {}
                }
            
            self.logger.info(f"Claude analysis completed. Tokens used: {self.total_tokens_used}")
            
            return parsed_response
            
        except Exception as e:
            self.logger.error(f"Claude analysis failed: {e}")
            return {
                'analysis': 'AI analysis failed',
                'error': str(e),
                'structured_data': {}
            }
    
    def _parse_structured_response(self, response_text: str) -> Dict[str, Any]:
        """
        Parse Claude's response for structured data.
        
        Looks for JSON blocks, bullet points, and structured analysis.
        """
        structured_data = {
            'analysis': response_text,
            'attack_vectors': [],
            'test_priorities': [],
            'bypass_strategies': [],
            'exploitation_likelihood': 'unknown',
            'priority_findings': [],
            'next_steps': [],
            'impact_scenarios': [],
            'confidence_adjustment': 0,
            'false_positive_indicators': [],
            'additional_tests': [],
            'exploitability': 'unknown'
        }
        
        # Extract structured information using pattern matching
        lines = response_text.split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            
            # Detect sections
            if 'attack vector' in line.lower():
                current_section = 'attack_vectors'
                continue
            elif 'test priorit' in line.lower() or 'priority' in line.lower():
                current_section = 'test_priorities'
                continue
            elif 'bypass' in line.lower():
                current_section = 'bypass_strategies'
                continue
            elif 'next step' in line.lower():
                current_section = 'next_steps'
                continue
            elif 'impact' in line.lower():
                current_section = 'impact_scenarios'
                continue
            elif 'false positive' in line.lower():
                current_section = 'false_positive_indicators'
                continue
            elif 'additional test' in line.lower():
                current_section = 'additional_tests'
                continue
            
            # Extract likelihood/confidence values
            if 'likelihood' in line.lower():
                if 'high' in line.lower():
                    structured_data['exploitation_likelihood'] = 'high'
                elif 'medium' in line.lower():
                    structured_data['exploitation_likelihood'] = 'medium'
                elif 'low' in line.lower():
                    structured_data['exploitation_likelihood'] = 'low'
            
            # Extract exploitability assessment
            if 'exploitability' in line.lower():
                if 'high' in line.lower():
                    structured_data['exploitability'] = 'high'
                elif 'medium' in line.lower():
                    structured_data['exploitability'] = 'medium'
                elif 'low' in line.lower():
                    structured_data['exploitability'] = 'low'
            
            # Extract list items
            if line.startswith('-') or line.startswith('•') or line.startswith('*'):
                item = line[1:].strip()
                if current_section and item:
                    structured_data[current_section].append(item)
            
            # Extract numbered items
            elif line and line[0].isdigit() and '.' in line:
                item = line.split('.', 1)[1].strip()
                if current_section and item:
                    structured_data[current_section].append(item)
        
        return structured_data
    
    async def analyze_reconnaissance(self, recon_data: Dict[str, Any]) -> Dict[str, Any]:
        """Specialized reconnaissance analysis."""
        
        prompt = f"""
        Analyze this HTTP infrastructure for HTTP Request Smuggling vulnerabilities:

        Target: {recon_data.get('url')}
        Server: {recon_data.get('tech_fingerprint', {}).get('web_server', {})}
        CDN: {recon_data.get('tech_fingerprint', {}).get('cdn_provider', {})}
        WAF: {recon_data.get('tech_fingerprint', {}).get('waf_detected', {})}
        Architecture: {recon_data.get('architecture', {})}

        Based on James Kettle's "HTTP/1.1 Must Die" research, provide:
        1. Top 3 most promising desync techniques for this stack
        2. Specific test recommendations
        3. WAF bypass strategies if applicable
        4. Risk assessment (high/medium/low)

        Focus on actionable intelligence for bug bounty hunting.
        """
        
        return await self.analyze(prompt, recon_data)
    
    async def analyze_detection_results(self, detection_data: Dict[str, Any]) -> Dict[str, Any]:
        """Specialized detection results analysis."""
        
        prompt = f"""
        Analyze these HTTP Request Smuggling detection results:

        Target: {detection_data.get('target_url')}
        Findings: {len(detection_data.get('findings', []))} potential vulnerabilities
        Techniques Tested: {[f.get('technique') for f in detection_data.get('findings', [])]}
        
        Detection Details:
        {json.dumps(detection_data.get('findings', []), indent=2)}

        Provide:
        1. Likelihood assessment for each finding (high/medium/low)
        2. Priority ranking for validation
        3. Exploitation feasibility analysis
        4. Expected impact scenarios
        5. Recommended next steps

        Focus on eliminating false positives and maximizing bug bounty success.
        """
        
        return await self.analyze(prompt, detection_data)
    
    async def analyze_validation_results(self, validation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Specialized validation analysis."""
        
        prompt = f"""
        Analyze this vulnerability validation data:

        Finding: {validation_data.get('original_finding', {}).get('technique')}
        Confidence Score: {validation_data.get('confidence_score', 0)}
        Validation Layers: {list(validation_data.get('validation_layers', {}).keys())}
        
        Validation Results:
        {json.dumps(validation_data.get('validation_layers', {}), indent=2)}

        Assess:
        1. Is this a genuine vulnerability? (high/medium/low confidence)
        2. Any red flags suggesting false positive?
        3. Recommended confidence adjustment (-0.2 to +0.2)
        4. Additional validation tests needed?
        5. Exploitation potential for bug bounty

        Provide definitive guidance on proceeding with this finding.
        """
        
        return await self.analyze(prompt, validation_data)
    
    async def generate_exploit_strategy(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate exploitation strategy."""
        
        prompt = f"""
        Generate exploitation strategy for this validated vulnerability:

        Technique: {finding_data.get('technique')}
        Target: {finding_data.get('target_url')}
        Confidence: {finding_data.get('confidence_score', 0)}
        Evidence: {finding_data.get('evidence', {})}

        Based on the specific technique and target infrastructure:
        1. Detailed exploitation steps
        2. Payload recommendations
        3. Expected behavior and responses
        4. Impact demonstration methods
        5. PoC development guidance

        Focus on creating a compelling bug bounty report.
        """
        
        return await self.analyze(prompt, finding_data)
    
    def get_usage_stats(self) -> Dict[str, Any]:
        """Get API usage statistics."""
        return {
            'total_tokens_used': self.total_tokens_used,
            'requests_made': self.requests_made,
            'average_tokens_per_request': self.total_tokens_used / max(self.requests_made, 1)
        }
