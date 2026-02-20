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
    
    def execute(self, target: Target, http_client: HttpClientProtocol) -> List[Vulnerability]:
        vulnerabilities = []
        
        try:
            test_origin = "https://malicious-site.com"
            
            response = http_client.options(
                target.normalized_url,
                timeout=10,
                headers={'Origin': test_origin}
            )
            
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            
            acao_header = response_headers.get('access-control-allow-origin')
            acac_header = response_headers.get('access-control-allow-credentials')
            
            if acao_header == '*':
                vulnerabilities.append(Vulnerability(
                    id="CORS-WILDCARD_ORIGIN",
                    title="CORS permite qualquer origem (*)",
                    severity=Severity.CRITICAL,
                    module_name=self.name,
                    description="Access-Control-Allow-Origin configurado como *, permitindo qualquer site fazer requisições",
                    evidence=f"Access-Control-Allow-Origin: {acao_header}",
                    recommendation="Restringir origens permitidas para domínios específicos confiáveis",
                    reference="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
                ))
            
            if acao_header and acac_header and acac_header.lower() == 'true':
                if acao_header == '*':
                    vulnerabilities.append(Vulnerability(
                        id="CORS-CREDENTIALS_WITH_WILDCARD",
                        title="CORS permite credenciais com origem wildcard",
                        severity=Severity.CRITICAL,
                        module_name=self.name,
                        description="Access-Control-Allow-Credentials: true combinado com origem wildcard",
                        evidence=f"ACAO: {acao_header}, ACAC: {acac_header}",
                        recommendation="Nunca usar wildcard (*) quando credentials estiver habilitado",
                        reference="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
                    ))
                
                elif acao_header == test_origin:
                    vulnerabilities.append(Vulnerability(
                        id="CORS-REFLECTS_ORIGIN",
                        title="CORS reflete origem sem validação",
                        severity=Severity.HIGH,
                        module_name=self.name,
                        description="Servidor reflete qualquer origem enviada sem validação apropriada",
                        evidence=f"Origin enviada: {test_origin}, ACAO retornado: {acao_header}",
                        recommendation="Implementar whitelist de origens permitidas ao invés de refletir",
                        reference="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
                    ))
            
            acam_header = response_headers.get('access-control-allow-methods')
            if acam_header:
                dangerous_methods = ['PUT', 'DELETE', 'PATCH', 'TRACE']
                allowed_methods = [m.strip().upper() for m in acam_header.split(',')]
                
                found_dangerous = [m for m in dangerous_methods if m in allowed_methods]
                
                if found_dangerous:
                    vulnerabilities.append(Vulnerability(
                        id="CORS-DANGEROUS_METHODS",
                        title="CORS permite métodos HTTP perigosos",
                        severity=Severity.MEDIUM,
                        module_name=self.name,
                        description=f"Métodos perigosos permitidos via CORS: {', '.join(found_dangerous)}",
                        evidence=f"Access-Control-Allow-Methods: {acam_header}",
                        recommendation="Restringir métodos CORS apenas aos necessários (GET, POST)",
                        reference="https://owasp.org/www-community/attacks/CORS_RequestPreflighScrutiny"
                    ))
        
        except Exception as e:
            raise RuntimeError(f"Erro ao verificar CORS: {str(e)}")
        
        return vulnerabilities