"""Módulo avançado de verificação de SQL Injection."""

from typing import List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from src.domain import Target, Vulnerability, Severity
from src.application.contracts import HttpClientProtocol


class SQLInjectionModule:

    name = "sql_injection_module"
    description = "Detecção avançada de SQL Injection (error-based)"
    category = "injection"
    priority = 1
    enabled = True

    SQL_ERROR_PATTERNS = [
        "you have an error in your sql",
        "sql syntax",
        "warning: mysql",
        "unclosed quotation mark",
        "quoted string not properly terminated",
        "postgresql",
        "sqlite error",
        "ora-01756"
    ]

    PAYLOADS = [
        "'",
        "' OR '1'='1",
        "'--",
        "\" OR \"1\"=\"1"
    ]

    def execute(self, target: Target, http_client: HttpClientProtocol) -> List[Vulnerability]:
        vulnerabilities = []

        try:
            parsed_url = urlparse(target.normalized_url)
            query_params = parse_qs(parsed_url.query)

            if not query_params:
                return vulnerabilities

            # 🔎 Baseline request
            baseline_response = http_client.get(target.normalized_url, timeout=10)
            baseline_text = baseline_response.text.lower()
            baseline_status = baseline_response.status_code
            baseline_length = len(baseline_response.text)

            for param in query_params.keys():
                for payload in self.PAYLOADS:

                    injected_params = query_params.copy()
                    injected_params[param] = [payload]

                    new_query = urlencode(injected_params, doseq=True)
                    injected_url = urlunparse(
                        parsed_url._replace(query=new_query)
                    )

                    response = http_client.get(injected_url, timeout=10)
                    response_text = response.text.lower()
                    response_status = response.status_code
                    response_length = len(response.text)

                    error_detected = any(
                        pattern in response_text and pattern not in baseline_text
                        for pattern in self.SQL_ERROR_PATTERNS
                    )

                    status_changed = response_status != baseline_status
                    length_diff = abs(response_length - baseline_length) > 100

                    confidence = self._calculate_confidence(
                        error_detected,
                        status_changed,
                        length_diff
                    )

                    if confidence:

                        vuln_id = f"SQLI-{param.upper()}"

                        vulnerabilities.append(Vulnerability(
                            id=vuln_id,
                            title=f"Possível SQL Injection no parâmetro '{param}'",
                            severity=Severity.HIGH,
                            module_name=self.name,
                            description="Possível vulnerabilidade de SQL Injection detectada através de análise diferencial.",
                            evidence=(
                                f"Payload: {payload} | "
                                f"Status mudou: {status_changed} | "
                                f"Diferença tamanho: {response_length - baseline_length}"
                            ),
                            recommendation="Utilizar prepared statements, ORM seguro e validação rigorosa de entrada.",
                            reference="https://owasp.org/www-community/attacks/SQL_Injection"
                        ))

                        # Se alta confiança, não precisa continuar testando o mesmo parâmetro
                        if confidence == "high":
                            return vulnerabilities

        except Exception as e:
            raise RuntimeError(f"Erro ao verificar SQL Injection: {str(e)}")

        return vulnerabilities

    def _calculate_confidence(self, error_detected: bool, status_changed: bool, length_diff: bool) -> str | None:
        """
        Define nível de confiança baseado em múltiplos fatores.
        """

        if error_detected and status_changed:
            return "high"

        if error_detected or (status_changed and length_diff):
            return "medium"

        if status_changed:
            return "low"

        return None