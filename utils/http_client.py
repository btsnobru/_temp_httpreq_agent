
import asyncio
import aiohttp
import logging
import time
from typing import Dict, Any, Optional, Union
import ssl

class HTTPClient:
    """
    Asynchronous HTTP client optimized for HTTP Request Smuggling detection.
    
    Features:
    - Connection reuse for timing consistency
    - Raw header manipulation capabilities
    - Detailed response timing tracking
    - SSL/TLS configuration options
    - Rate limiting and backoff strategies
    """
    
    def __init__(self, timeout: int = 30, max_connections: int = 100):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.max_connections = max_connections
        self.logger = logging.getLogger(__name__)
        
        # SSL context for bypassing certificate verification if needed
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE
        
        # Connection pool
        self.connector = None
        self.session = None
        
        # Rate limiting
        self.last_request_time = 0
        self.min_request_interval = 0.1  # 100ms minimum between requests
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self._ensure_session()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
    
    async def _ensure_session(self):
        """Ensure aiohttp session is initialized."""
        if self.session is None or self.session.closed:
            self.connector = aiohttp.TCPConnector(
                limit=self.max_connections,
                ssl=self.ssl_context,
                enable_cleanup_closed=True
            )
            
            self.session = aiohttp.ClientSession(
                connector=self.connector,
                timeout=self.timeout,
                headers={
                    'User-Agent': 'DesyncHunter/1.0 (HTTP Request Smuggling Scanner)'
                }
            )
    
    async def close(self):
        """Close the HTTP session and connections."""
        if self.session and not self.session.closed:
            await self.session.close()
        if self.connector:
            await self.connector.close()
    
    async def _rate_limit(self):
        """Apply rate limiting between requests."""
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        if time_since_last < self.min_request_interval:
            sleep_time = self.min_request_interval - time_since_last
            await asyncio.sleep(sleep_time)
        
        self.last_request_time = time.time()
    
    async def request(
        self, 
        method: str, 
        url: str, 
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Union[str, bytes]] = None,
        json: Optional[Dict[str, Any]] = None,
        allow_redirects: bool = True,
        **kwargs
    ) -> 'HTTPResponse':
        """
        Make an HTTP request with detailed timing and response tracking.
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            headers: Custom headers
            data: Request body data
            json: JSON data (will be serialized)
            allow_redirects: Whether to follow redirects
            **kwargs: Additional aiohttp parameters
            
        Returns:
            HTTPResponse object with timing and response data
        """
        await self._ensure_session()
        await self._rate_limit()
        
        # Prepare headers
        request_headers = headers or {}
        
        # Track timing
        start_time = time.time()
        
        try:
            async with self.session.request(
                method=method.upper(),
                url=url,
                headers=request_headers,
                data=data,
                json=json,
                allow_redirects=allow_redirects,
                **kwargs
            ) as response:
                
                end_time = time.time()
                response_time = end_time - start_time
                
                # Read response content
                content = await response.read()
                text_content = content.decode('utf-8', errors='ignore')
                
                return HTTPResponse(
                    status=response.status,
                    headers=dict(response.headers),
                    content=content,
                    text=text_content,
                    url=str(response.url),
                    response_time=response_time,
                    method=method.upper()
                )
                
        except asyncio.TimeoutError:
            self.logger.warning(f"Request timeout for {method} {url}")
            raise
        except Exception as e:
            self.logger.error(f"Request failed for {method} {url}: {e}")
            raise
    
    async def get(self, url: str, **kwargs) -> 'HTTPResponse':
        """GET request."""
        return await self.request('GET', url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> 'HTTPResponse':
        """POST request."""
        return await self.request('POST', url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> 'HTTPResponse':
        """HEAD request."""
        return await self.request('HEAD', url, **kwargs)
    
    async def options(self, url: str, **kwargs) -> 'HTTPResponse':
        """OPTIONS request."""
        return await self.request('OPTIONS', url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> 'HTTPResponse':
        """PUT request."""
        return await self.request('PUT', url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> 'HTTPResponse':
        """DELETE request."""
        return await self.request('DELETE', url, **kwargs)
    
    async def patch(self, url: str, **kwargs) -> 'HTTPResponse':
        """PATCH request."""
        return await self.request('PATCH', url, **kwargs)
    
    async def send_raw_request(self, raw_request: str, host: str, port: int = 80, use_ssl: bool = False) -> 'HTTPResponse':
        """
        Send a raw HTTP request for precise control over request format.
        Useful for testing malformed requests and smuggling techniques.
        
        Args:
            raw_request: Raw HTTP request string
            host: Target host
            port: Target port
            use_ssl: Whether to use SSL/TLS
            
        Returns:
            HTTPResponse object
        """
        start_time = time.time()
        
        try:
            # Create connection
            if use_ssl:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                reader, writer = await asyncio.open_connection(
                    host, port, ssl=context
                )
            else:
                reader, writer = await asyncio.open_connection(host, port)
            
            # Send raw request
            writer.write(raw_request.encode())
            await writer.drain()
            
            # Read response
            response_data = await reader.read(8192)  # Read up to 8KB
            
            # Close connection
            writer.close()
            await writer.wait_closed()
            
            end_time = time.time()
            response_time = end_time - start_time
            
            # Parse response
            response_text = response_data.decode('utf-8', errors='ignore')
            status_line = response_text.split('\n')[0] if response_text else 'HTTP/1.1 200 OK'
            
            try:
                status_code = int(status_line.split(' ')[1])
            except:
                status_code = 0
            
            return HTTPResponse(
                status=status_code,
                headers={},
                content=response_data,
                text=response_text,
                url=f"{'https' if use_ssl else 'http'}://{host}:{port}/",
                response_time=response_time,
                method='RAW'
            )
            
        except Exception as e:
            self.logger.error(f"Raw request failed for {host}:{port}: {e}")
            raise


class HTTPResponse:
    """
    HTTP response wrapper with additional metadata for vulnerability analysis.
    """
    
    def __init__(
        self, 
        status: int, 
        headers: Dict[str, str], 
        content: bytes, 
        text: str,
        url: str, 
        response_time: float, 
        method: str
    ):
        self.status = status
        self.headers = headers
        self.content = content
        self._text = text
        self.url = url
        self.response_time = response_time
        self.method = method
        self.timestamp = time.time()
    
    async def text(self) -> str:
        """Get response text content."""
        return self._text
    
    async def json(self) -> Dict[str, Any]:
        """Parse response as JSON."""
        import json
        return json.loads(self._text)
    
    def __str__(self) -> str:
        return f"<HTTPResponse [{self.status}] {self.method} {self.url}>"
    
    def __repr__(self) -> str:
        return self.__str__()
