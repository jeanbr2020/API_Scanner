from dataclasses import dataclass, field
from typing import Dict, List, TYPE_CHECKING

from .enums import Severity

if TYPE_CHECKING:
    from .entities import Scan


@dataclass(frozen=True)
class ScanResult:
    """
    Value Object que representa o resultado consolidado de um scan.
    É um DTO (Data Transfer Object) criado a partir de um Scan finalizado.
    Usado para apresentação de dados (CLI, relatórios, API).
    """
    
    target_url: str
    target_is_secure: bool
    
    scan_id: str
    
    total_vulnerabilities: int
    count_by_severity: Dict[str, int]
    
    score: int
    risk_level: str
    
    execution_time: float
    
    vulnerabilities_details: List[dict] = field(default_factory=list)
    
    @classmethod
    def from_scan(cls, scan: 'Scan') -> 'ScanResult':
        """
        Factory method: cria ScanResult a partir de um Scan finalizado.
        
        Args:
            scan: Instância de Scan já finalizada
            
        Returns:
            ScanResult com dados consolidados
            
        Raises:
            ValueError: Se scan não estiver finalizado (COMPLETED)
        """
        from .enums import ScanStatus
        
        if scan.status != ScanStatus.COMPLETED:
            raise ValueError(
                f"Não é possível criar ScanResult de scan não finalizado. "
                f"Status atual: {scan.status.value}"
            )
        
        severity_counts = scan.count_by_severity()
        count_by_severity_dict = {
            "critical": severity_counts[Severity.CRITICAL],
            "high": severity_counts[Severity.HIGH],
            "medium": severity_counts[Severity.MEDIUM],
            "low": severity_counts[Severity.LOW],
        }
        
        vulnerabilities_list = [
            {
                "id": vuln.id,
                "title": vuln.title,
                "severity": vuln.severity.value,
                "severity_label": vuln.get_severity_label(),
                "module_name": vuln.module_name,
                "description": vuln.description,
                "evidence": vuln.evidence,
                "recommendation": vuln.recommendation,
                "reference": vuln.reference,
                "timestamp": vuln.timestamp.isoformat()
            }
            for vuln in scan.vulnerabilities
        ]
        
        return cls(
            target_url=scan.target.normalized_url,
            target_is_secure=scan.target.is_secure,
            scan_id=scan.id,
            total_vulnerabilities=scan.get_total_vulnerabilities(),
            count_by_severity=count_by_severity_dict,
            score=scan.score,
            risk_level=scan.get_risk_level(),
            execution_time=scan.get_duration(),
            vulnerabilities_details=vulnerabilities_list
        )
    
    def get_risk_description(self) -> str:
        """Retorna descrição textual do nível de risco."""
        descriptions = {
            "A": "Seguro - Nenhum problema crítico encontrado",
            "B": "Baixo Risco - Poucos problemas de segurança",
            "C": "Risco Moderado - Atenção necessária",
            "D": "Alto Risco - Ação imediata recomendada"
        }
        return descriptions.get(self.risk_level, "Desconhecido")
    
    def has_vulnerabilities(self) -> bool:
        """Verifica se foram encontradas vulnerabilidades."""
        return self.total_vulnerabilities > 0
    
    def get_critical_count(self) -> int:
        """Retorna quantidade de vulnerabilidades críticas."""
        return self.count_by_severity.get("critical", 0)
    
    def get_high_count(self) -> int:
        """Retorna quantidade de vulnerabilidades altas."""
        return self.count_by_severity.get("high", 0)
    
    def get_medium_count(self) -> int:
        """Retorna quantidade de vulnerabilidades médias."""
        return self.count_by_severity.get("medium", 0)
    
    def get_low_count(self) -> int:
        """Retorna quantidade de vulnerabilidades baixas."""
        return self.count_by_severity.get("low", 0)
    
    def get_execution_time_formatted(self) -> str:
        """Retorna tempo de execução formatado."""
        if self.execution_time < 60:
            return f"{self.execution_time:.2f}s"
        else:
            minutes = int(self.execution_time // 60)
            seconds = self.execution_time % 60
            return f"{minutes}m {seconds:.2f}s"
    
    def get_vulnerabilities_by_severity(self, severity: str) -> list:
        """Retorna lista de vulnerabilidades de uma severidade específica."""
        if not self.vulnerabilities_details:
            return []
        return [v for v in self.vulnerabilities_details if v["severity"] == severity]
    
    def to_dict(self) -> dict:
        """Converte o resultado para dicionário (útil para JSON)."""
        result = {
            "target": {
                "url": self.target_url,
                "is_secure": self.target_is_secure
            },
            "scan_id": self.scan_id,
            "summary": {
                "total_vulnerabilities": self.total_vulnerabilities,
                "by_severity": self.count_by_severity,
                "score": self.score,
                "risk_level": self.risk_level,
                "risk_description": self.get_risk_description()
            },
            "execution": {
                "duration_seconds": self.execution_time,
                "duration_formatted": self.get_execution_time_formatted()
            }
        }
        
        if self.vulnerabilities_details:
            result["vulnerabilities"] = {
                "critical": self.get_vulnerabilities_by_severity("critical"),
                "high": self.get_vulnerabilities_by_severity("high"),
                "medium": self.get_vulnerabilities_by_severity("medium"),
                "low": self.get_vulnerabilities_by_severity("low")
            }
        
        return result
    
    def __str__(self) -> str:
        """Representação amigável do resultado."""
        return (
            f"Scan Result - {self.target_url}\n"
            f"Score: {self.score}/100 (Risk Level: {self.risk_level})\n"
            f"Vulnerabilities: {self.total_vulnerabilities} "
            f"(C:{self.get_critical_count()} H:{self.get_high_count()} "
            f"M:{self.get_medium_count()} L:{self.get_low_count()})\n"
            f"Duration: {self.get_execution_time_formatted()}"
        )
    
    def __repr__(self) -> str:
        """Representação técnica do resultado."""
        return (
            f"ScanResult(target={self.target_url}, score={self.score}, "
            f"risk={self.risk_level}, vulns={self.total_vulnerabilities})"
        )