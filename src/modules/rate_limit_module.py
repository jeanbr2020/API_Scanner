"""Módulo de verificação de rate limiting."""

from typing import List
import time
from src.domain import Target, Vulnerability, Severity
from src.application.contracts import HttpClientProtocol


class RateLimitModule:
    
    name = "rate_limit_module"
    description = "Verifica se a API possui rate limiting para prevenir brute force"
    category = "rate_limiting"
    priority = 2
    enabled = True
    
    REQUEST_COUNT = 20
    
    def execute(self, target: Target, http_client: HttpClientProtocol) -> List[Vulnerability]:
        vulnerabilities = []
        
        # Primeiro, verifica se o target é uma API REST
        try:
            initial_response = http_client.get(target.normalized_url, timeout=5)
            
            # Se não for API REST, não testa rate limit
            if not self._is_rest_api_response(initial_response):
                return vulnerabilities
        
        except Exception:
            return vulnerabilities
        
        # É API REST, continua testando rate limit
        start_time = time.time()
        successful_requests = 0
        rate_limited = False
        rate_limit_headers_found = False
        
        for i in range(self.REQUEST_COUNT):
            try:
                response = http_client.get(target.normalized_url, timeout=5)
                
                if response.status_code == 429:
                    rate_limited = True
                    break
                
                rate_limit_headers = [
                    'X-RateLimit-Limit',
                    'X-RateLimit-Remaining',
                    'X-Rate-Limit-Limit',
                    'X-Rate-Limit-Remaining',
                    'RateLimit-Limit',
                    'RateLimit-Remaining',
                    'Retry-After'
                ]
                
                if any(header in response.headers for header in rate_limit_headers):
                    rate_limit_headers_found = True
                    break
                
                if response.status_code in [200, 201, 202, 204]:
                    successful_requests += 1
                
                time.sleep(0.3)
            
            except Exception:
                pass
        
        end_time = time.time()
        duration = end_time - start_time
        
        if not rate_limited and not rate_limit_headers_found and successful_requests >= 15:
            vulnerabilities.append(Vulnerability(
                id="RATELIMIT-NO_LIMITING",
                title="Ausência de Rate Limiting",
                severity=Severity.MEDIUM,
                module_name=self.name,
                description=f"API aceitou {successful_requests} requisições em {duration:.2f}s sem rate limiting",
                evidence=f"Todas as {successful_requests} requisições retornaram 2xx/3xx sem headers de rate limit",
                recommendation="Implementar rate limiting para prevenir brute force e DDoS",
                reference="https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"
            ))
        
        return vulnerabilities
    
    def _is_rest_api_response(self, response) -> bool:
        """
        Verifica se a resposta é de uma API REST.
        APIs REST retornam JSON ou XML.
        Se retornar HTML, não é API REST.
        """
        content_type = response.headers.get('content-type', '').lower()
        
        return (
            'application/json' in content_type or
            'application/xml' in content_type or
            'text/xml' in content_type
        )