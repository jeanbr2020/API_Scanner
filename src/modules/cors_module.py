"""Módulo de verificação de CORS (Cross-Origin Resource Sharing)."""

from typing import List
from src.domain import Target, Vulnerability, Severity
from src.application.contracts import HttpClientProtocol


class CorsModule:
    
    name = "cors_module"
    description = "Verifica configuração de CORS e possíveis misconfigurações"
    category = "cors"
    priority = 1
    enabled = True
    
    # Usando domínio reservado para testes (RFC 2606)
    TEST_ORIGIN = "https://attacker.example.com"
    
    def execute(self, target: Target, http_client: HttpClientProtocol) -> List[Vulnerability]:
        vulnerabilities = []
        
        try:
            response = http_client.options(
                target.normalized_url,
                timeout=5,
                headers={
                    'Origin': self.TEST_ORIGIN,
                    'Access-Control-Request-Method': 'GET',
                    'Access-Control-Request-Headers': 'Content-Type'
                }
            )
            
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            acac = response.headers.get('Access-Control-Allow-Credentials', '').lower()
            acam = response.headers.get('Access-Control-Allow-Methods', '')
            
            if acao == '*':
                severity = Severity.CRITICAL if acac == 'true' else Severity.CRITICAL
                
                vulnerabilities.append(Vulnerability(
                    id="CORS-WILDCARD_ORIGIN",
                    title="CORS permite qualquer origem (*)",
                    severity=severity,
                    module_name=self.name,
                    description="Access-Control-Allow-Origin configurado como *, permitindo qualquer site fazer requisições",
                    evidence=f"Access-Control-Allow-Origin: {acao}",
                    recommendation="Restringir origens permitidas para domínios específicos confiáveis",
                    reference="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
                ))
                
                if acac == 'true':
                    vulnerabilities.append(Vulnerability(
                        id="CORS-WILDCARD_WITH_CREDENTIALS",
                        title="CORS permite wildcard com credentials",
                        severity=Severity.CRITICAL,
                        module_name=self.name,
                        description="Combinação perigosa: wildcard origin + credentials habilitado",
                        evidence=f"ACAO: {acao}, ACAC: {acac}",
                        recommendation="Nunca usar wildcard (*) com credentials habilitado",
                        reference="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
                    ))
            
            elif acao == self.TEST_ORIGIN:
                vulnerabilities.append(Vulnerability(
                    id="CORS-REFLECTS_ORIGIN",
                    title="CORS reflete origem sem validação",
                    severity=Severity.HIGH,
                    module_name=self.name,
                    description="Servidor reflete qualquer origem enviada sem validação apropriada",
                    evidence=f"Origin enviada: {self.TEST_ORIGIN}, ACAO retornado: {acao}",
                    recommendation="Implementar whitelist de origens permitidas ao invés de refletir",
                    reference="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
                ))
            
            if acam:
                dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE']
                found_dangerous = [m for m in dangerous_methods if m in acam.upper()]
                
                if found_dangerous:
                    vulnerabilities.append(Vulnerability(
                        id="CORS-DANGEROUS_METHODS",
                        title="CORS permite métodos HTTP perigosos",
                        severity=Severity.MEDIUM,
                        module_name=self.name,
                        description=f"Métodos perigosos permitidos via CORS: {', '.join(found_dangerous)}",
                        evidence=f"Access-Control-Allow-Methods: {acam}",
                        recommendation="Restringir métodos CORS apenas aos necessários (GET, POST)",
                        reference="https://owasp.org/www-community/attacks/CORS_RequestPreflighScrutiny"
                    ))
        
        except Exception:
            pass
        
        return vulnerabilities