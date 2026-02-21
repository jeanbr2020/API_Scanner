"""Módulo de verificação de autenticação e controle de acesso."""

from typing import List
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.domain import Target, Vulnerability, Severity
from src.application.contracts import HttpClientProtocol


class AuthenticationModule:
    
    name = "authentication_module"
    description = "Detecta falhas de autenticação e bypass de controle de acesso"
    category = "authentication"
    priority = 4
    enabled = True
    
    CRITICAL_ENDPOINTS = [
        "/admin",
        "/api/admin",
        "/api/admin/users",
        "/api/config",
        "/api/settings",
        "/console",
        "/api/internal",
    ]
    
    HIGH_ENDPOINTS = [
        "/api/users",
        "/api/customers",
        "/api/orders",
        "/api/payments",
        "/api/transactions",
        "/api/dashboard",
        "/api/reports",
    ]
    
    MEDIUM_ENDPOINTS = [
        "/api/profile",
        "/api/account",
        "/api/me",
        "/api/user",
        "/api/data",
    ]
    
    LOW_ENDPOINTS = [
        "/api/status",
        "/api/health",
        "/api/metrics",
        "/api/logs",
        "/api/debug",
    ]
    
    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]
    
    BYPASS_SCENARIOS = [
        {"name": "empty_token", "headers": {"Authorization": "Bearer "}},
        {"name": "invalid_token", "headers": {"Authorization": "Bearer invalid_token_12345"}},
        {"name": "malformed_token", "headers": {"Authorization": "Bearer eyJhbGciOiJub25lIn0"}},
    ]
    
    MAX_WORKERS = 5
    REQUEST_DELAY = 0.3
    REQUEST_TIMEOUT = 3
    
    def execute(self, target: Target, http_client: HttpClientProtocol) -> List[Vulnerability]:
        vulnerabilities = []
        
        all_endpoints = (
            self.CRITICAL_ENDPOINTS +
            self.HIGH_ENDPOINTS +
            self.MEDIUM_ENDPOINTS +
            self.LOW_ENDPOINTS
        )
        
        with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as executor:
            futures = {
                executor.submit(
                    self._test_endpoint_all_methods,
                    http_client,
                    target,
                    endpoint
                ): endpoint
                for endpoint in all_endpoints
            }
            
            for future in as_completed(futures):
                try:
                    endpoint_vulns = future.result()
                    vulnerabilities.extend(endpoint_vulns)
                except Exception:
                    pass
        
        return vulnerabilities
    
    def _test_endpoint_all_methods(
        self,
        http_client: HttpClientProtocol,
        target: Target,
        endpoint: str
    ) -> List[Vulnerability]:
        vulnerabilities = []
        full_url = f"{target.normalized_url}{endpoint}"
        severity = self._get_endpoint_severity(endpoint)
        
        endpoint_exists = False
        
        for method in self.HTTP_METHODS:
            method_vulns = self._test_endpoint_method(
                http_client,
                full_url,
                endpoint,
                method,
                severity
            )
            
            if method_vulns:
                endpoint_exists = True
                vulnerabilities.extend(method_vulns)
            
            if method == "GET" and not method_vulns:
                break
            
            time.sleep(self.REQUEST_DELAY)
        
        return vulnerabilities
    
    def _is_rest_api_response(self, response) -> bool:
        """
        Verifica se a resposta é de uma API REST.
        APIs REST retornam JSON ou XML, não HTML.
        """
        content_type = response.headers.get('content-type', '').lower()
        
        return (
            'application/json' in content_type or
            'application/xml' in content_type or
            'text/xml' in content_type
        )
    
    def _test_endpoint_method(
        self,
        http_client: HttpClientProtocol,
        full_url: str,
        endpoint: str,
        method: str,
        severity: Severity
    ) -> List[Vulnerability]:
        vulnerabilities = []
        
        try:
            response = self._make_request(http_client, full_url, method)
            
            if response.status_code == 404:
                return vulnerabilities
            
            if response.status_code >= 500:
                return vulnerabilities
            
            if response.status_code in [401, 403]:
                return vulnerabilities
            
            if response.status_code == 200:
                if not self._is_rest_api_response(response):
                    return vulnerabilities
                # VERIFICA SE É REALMENTE API REST
                if not self._is_rest_api_response(response):
                    return vulnerabilities
                
                vulnerabilities.append(Vulnerability(
                    id=f"AUTH-NO_AUTH_REQUIRED-{method}",
                    title=f"Endpoint {method} acessível sem autenticação: {endpoint}",
                    severity=severity,
                    module_name=self.name,
                    description=f"Endpoint sensível retornou dados sem exigir autenticação usando método {method}",
                    evidence=f"{method} {endpoint} retornou status 200 sem Authorization header",
                    recommendation="Implementar autenticação obrigatória no endpoint",
                    reference="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
                ))
                
                bypass_vulns = self._test_bypass(
                    http_client,
                    full_url,
                    endpoint,
                    method
                )
                vulnerabilities.extend(bypass_vulns)
        
        except Exception:
            pass
        
        return vulnerabilities
    
    def _test_bypass(
        self,
        http_client: HttpClientProtocol,
        full_url: str,
        endpoint: str,
        method: str
    ) -> List[Vulnerability]:
        vulnerabilities = []
        
        for scenario in self.BYPASS_SCENARIOS:
            try:
                time.sleep(self.REQUEST_DELAY)
                
                response = self._make_request(
                    http_client,
                    full_url,
                    method,
                    headers=scenario["headers"]
                )
                
                if response.status_code == 200:
                    if not self._is_rest_api_response(response):
                        continue
                    # VERIFICA SE É REALMENTE API REST
                    if not self._is_rest_api_response(response):
                        continue
                    
                    scenario_name = scenario["name"].replace("_", " ").title()
                    auth_header = scenario["headers"].get("Authorization", "")
                    
                    vulnerabilities.append(Vulnerability(
                        id=f"AUTH-BYPASS-{scenario['name'].upper()}-{method}",
                        title=f"Bypass de autenticação ({scenario_name}) no método {method}: {endpoint}",
                        severity=Severity.HIGH,
                        module_name=self.name,
                        description=f"Endpoint aceita requisição com {scenario_name.lower()}, permitindo bypass de autenticação",
                        evidence=f"{method} {endpoint} com '{auth_header}' retornou status 200",
                        recommendation="Validar presença e formato do token antes de processar requisição",
                        reference="https://owasp.org/API-Security/editions/2023/en/0xa2-broken-authentication/"
                    ))
            
            except Exception:
                continue
        
        return vulnerabilities
    
    def _is_rest_api_response(self, response) -> bool:
        """
        Verifica se a resposta é de uma API REST.
        APIs REST retornam JSON ou XML.
        Se retornar HTML ou outro formato, não é API REST.
        """
        content_type = response.headers.get('content-type', '').lower()
        
        return (
            'application/json' in content_type or
            'application/xml' in content_type or
            'text/xml' in content_type
        )
    
    def _make_request(
        self,
        http_client: HttpClientProtocol,
        url: str,
        method: str,
        headers: dict = None
    ):
        kwargs = {"timeout": self.REQUEST_TIMEOUT}
        if headers:
            kwargs["headers"] = headers
        
        if method == "GET":
            return http_client.get(url, **kwargs)
        elif method == "POST":
            return http_client.post(url, **kwargs)
        elif method == "PUT":
            import requests
            kwargs["verify"] = True
            return requests.put(url, **kwargs)
        elif method == "DELETE":
            import requests
            kwargs["verify"] = True
            return requests.delete(url, **kwargs)
    
    def _get_endpoint_severity(self, endpoint: str) -> Severity:
        if endpoint in self.CRITICAL_ENDPOINTS:
            return Severity.CRITICAL
        elif endpoint in self.HIGH_ENDPOINTS:
            return Severity.HIGH
        elif endpoint in self.MEDIUM_ENDPOINTS:
            return Severity.MEDIUM
        else:
            return Severity.LOW