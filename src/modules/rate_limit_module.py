"""Módulo de verificação de Rate Limiting."""

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
    
    def execute(self, target: Target, http_client: HttpClientProtocol) -> List[Vulnerability]:
        vulnerabilities = []
        
        try:
            test_requests = 20
            start_time = time.time()
            
            status_codes = []
            rate_limit_headers_found = False
            
            for i in range(test_requests):
                try:
                    response = http_client.get(target.normalized_url, timeout=5)
                    status_codes.append(response.status_code)
                    
                    response_headers = {k.lower(): v for k, v in response.headers.items()}
                    
                    rate_limit_indicators = [
                        'x-ratelimit-limit',
                        'x-ratelimit-remaining',
                        'x-rate-limit-limit',
                        'ratelimit-limit',
                        'retry-after'
                    ]
                    
                    if any(indicator in response_headers for indicator in rate_limit_indicators):
                        rate_limit_headers_found = True
                        break
                    
                    if response.status_code == 429:
                        rate_limit_headers_found = True
                        break
                    
                    time.sleep(0.1)
                
                except Exception:
                    continue
            
            end_time = time.time()
            duration = end_time - start_time
            
            all_success = all(code < 400 for code in status_codes if code)
            
            if not rate_limit_headers_found and all_success and len(status_codes) >= test_requests:
                vulnerabilities.append(Vulnerability(
                    id="RATELIMIT-NO_LIMITING",
                    title="Ausência de Rate Limiting",
                    severity=Severity.MEDIUM,
                    module_name=self.name,
                    description=f"API aceitou {test_requests} requisições em {duration:.2f}s sem rate limiting",
                    evidence=f"Todas as {test_requests} requisições retornaram 2xx/3xx sem headers de rate limit",
                    recommendation="Implementar rate limiting para prevenir brute force e DDoS",
                    reference="https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"
                ))
            
            if rate_limit_headers_found:
                pass
        
        except Exception as e:
            raise RuntimeError(f"Erro ao verificar rate limiting: {str(e)}")
        
        return vulnerabilities