"""Módulo de verificação de Security Headers."""

from typing import List
from src.domain import Target, Vulnerability, Severity
from src.application.contracts import HttpClientProtocol


class HeadersModule:
    
    name = "headers_module"
    description = "Verifica presença de security headers importantes"
    category = "headers"
    priority = 0
    enabled = True
    
    SECURITY_HEADERS = {
        'X-Frame-Options': {
            'severity': Severity.MEDIUM,
            'description': 'Protege contra clickjacking',
            'recommendation': 'Adicionar: X-Frame-Options: DENY ou SAMEORIGIN',
            'reference': 'https://owasp.org/www-community/attacks/Clickjacking'
        },
        'X-Content-Type-Options': {
            'severity': Severity.MEDIUM,
            'description': 'Previne MIME type sniffing',
            'recommendation': 'Adicionar: X-Content-Type-Options: nosniff',
            'reference': 'https://owasp.org/www-project-secure-headers/#x-content-type-options'
        },
        'Strict-Transport-Security': {
            'severity': Severity.HIGH,
            'description': 'Força uso de HTTPS',
            'recommendation': 'Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'reference': 'https://owasp.org/www-project-secure-headers/#http-strict-transport-security'
        },
        'X-XSS-Protection': {
            'severity': Severity.LOW,
            'description': 'Ativa proteção XSS do browser (deprecated mas ainda útil)',
            'recommendation': 'Adicionar: X-XSS-Protection: 1; mode=block',
            'reference': 'https://owasp.org/www-community/attacks/xss/'
        },
        'Content-Security-Policy': {
            'severity': Severity.HIGH,
            'description': 'Previne XSS e injection attacks',
            'recommendation': 'Adicionar Content-Security-Policy com diretivas apropriadas',
            'reference': 'https://owasp.org/www-project-secure-headers/#content-security-policy'
        },
        'Referrer-Policy': {
            'severity': Severity.LOW,
            'description': 'Controla informação de referrer enviada',
            'recommendation': 'Adicionar: Referrer-Policy: strict-origin-when-cross-origin',
            'reference': 'https://owasp.org/www-project-secure-headers/#referrer-policy'
        },
        'Permissions-Policy': {
            'severity': Severity.LOW,
            'description': 'Controla features e APIs do browser',
            'recommendation': 'Adicionar Permissions-Policy restringindo features não utilizadas',
            'reference': 'https://owasp.org/www-project-secure-headers/#permissions-policy'
        }
    }
    
    def execute(self, target: Target, http_client: HttpClientProtocol) -> List[Vulnerability]:
        vulnerabilities = []
        
        try:
            response = http_client.get(target.normalized_url, timeout=10)
            
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            
            for header_name, header_info in self.SECURITY_HEADERS.items():
                if header_name.lower() not in response_headers:
                    vuln_id = f"HEADERS-{header_name.upper().replace('-', '_')}"
                    
                    vulnerabilities.append(Vulnerability(
                        id=vuln_id,
                        title=f"Missing Security Header: {header_name}",
                        severity=header_info['severity'],
                        module_name=self.name,
                        description=header_info['description'],
                        evidence=f"Header '{header_name}' não encontrado na resposta",
                        recommendation=header_info['recommendation'],
                        reference=header_info['reference']
                    ))
            
            if target.is_secure and 'Strict-Transport-Security'.lower() not in response_headers:
                vulnerabilities.append(Vulnerability(
                    id="HEADERS-HSTS_MISSING_HTTPS",
                    title="HSTS ausente em site HTTPS",
                    severity=Severity.HIGH,
                    module_name=self.name,
                    description="Site usa HTTPS mas não define HSTS, permitindo downgrade attacks",
                    evidence="Strict-Transport-Security header ausente",
                    recommendation="Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    reference="https://owasp.org/www-project-secure-headers/#http-strict-transport-security"
                ))
        
        except Exception as e:
            raise RuntimeError(f"Erro ao verificar headers: {str(e)}")
        
        return vulnerabilities