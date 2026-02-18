from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse
from typing import Optional, List, Dict

import ipaddress
import uuid

from .exceptions import InvalidTargetError, PrivateIPNotAllowedError, InvalidSeverityError, InvalidScanStateError
from .enums import Severity, ScanStatus

@dataclass
class Target:
    """Representa o alvo de um scan de segurança."""
    
    raw_url: str  # URL fornecida pelo usuário
    
    # Campos computados (preenchidos no __post_init__)
    normalized_url: str = None
    scheme: str = None
    host: str = None
    port: Optional[int] = None
    is_secure: bool = None
    
    def __post_init__(self):
        """Valida e normaliza a URL após inicialização."""
        self._validate_and_normalize()
        self._validate_private_ip()
    
    def _validate_and_normalize(self):
        """Valida formato e normaliza a URL."""
        url = self.raw_url.strip()
        
        # Se não tem scheme, adiciona https://
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        # Parse da URL
        try:
            parsed = urlparse(url)
        except Exception as e:
            raise InvalidTargetError(self.raw_url, f"Erro ao parsear URL: {e}")
        
        # Validações
        if not parsed.scheme:
            raise InvalidTargetError(self.raw_url, "Scheme ausente")
        
        if parsed.scheme not in ('http', 'https'):
            raise InvalidTargetError(self.raw_url, f"Scheme inválido: {parsed.scheme}")
        
        if not parsed.netloc:
            raise InvalidTargetError(self.raw_url, "Host ausente")
        
        # Preenche os campos
        self.normalized_url = url
        self.scheme = parsed.scheme
        self.host = parsed.hostname or parsed.netloc
        self.port = parsed.port
        self.is_secure = (parsed.scheme == 'https')
    
    def _validate_private_ip(self):
        """Valida que o host não é um IP privado."""
        try:
            # Tenta converter para IP
            ip = ipaddress.ip_address(self.host)
            
            # Verifica se é privado ou loopback
            if ip.is_private or ip.is_loopback:
                raise PrivateIPNotAllowedError(self.host)
                
        except ValueError:
            # Não é um IP, é um domínio - OK
            pass
    
    def __str__(self) -> str:
        """Representação amigável do Target."""
        return self.normalized_url
    
    def __repr__(self) -> str:
        """Representação técnica do Target."""
        return f"Target(url={self.normalized_url}, secure={self.is_secure})"
    


@dataclass(frozen=True)
@dataclass(frozen=True)
class Vulnerability:
    """Representa uma vulnerabilidade detectada durante o scan."""
    
    # Campos obrigatórios
    id: str
    title: str
    severity: Severity
    module_name: str
    
    # Campos opcionais (versão futura)
    description: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    reference: Optional[str] = None
    
    # Campo computado automaticamente
    timestamp: datetime = None
    
    def __post_init__(self):
        """Valida os dados e gera timestamp automaticamente."""
        # Validação de severidade
        self._validate_severity()
        
        # Validação leve do formato do ID
        self._validate_id_format()
        
        # Gera timestamp se não foi fornecido
        if self.timestamp is None:
            object.__setattr__(self, 'timestamp', datetime.now())
    
    def _validate_severity(self):
        """Valida que severity é um Severity válido."""
        if not isinstance(self.severity, Severity):
            raise InvalidSeverityError(self.severity)
    
    def _validate_id_format(self):
        """Valida formato sugerido do ID (leve, não estrito)."""
        if not self.id or not self.id.strip():
            raise ValueError("ID não pode ser vazio")
        
        # Sugestão de formato: MODULE-CATEGORY-NUMBER
        # Mas não força, apenas avisa se não seguir
        parts = self.id.split('-')
        if len(parts) < 2:
            # Apenas um aviso no futuro, por enquanto aceita
            pass
    
    def get_severity_label(self) -> str:
        """Retorna o label da severidade em português."""
        return self.severity.get_label()
    
    def get_severity_weight(self) -> int:
        """Retorna o peso da severidade para cálculo de score."""
        return self.severity.get_weight()
    
    def __str__(self) -> str:
        """Representação amigável da vulnerabilidade."""
        return f"[{self.severity.get_label()}] {self.title} (ID: {self.id})"
    
    def __repr__(self) -> str:
        """Representação técnica da vulnerabilidade."""
        return (f"Vulnerability(id={self.id}, title='{self.title}', "
                f"severity={self.severity.value}, module={self.module_name})")
    
@dataclass
class Scan:
    """Representa uma execução completa de scan de segurança."""
    
    target: 'Target'  # Referência ao Target (aspas para evitar import circular)
    
    # Campos com valores padrão
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    status: ScanStatus = ScanStatus.PENDING
    vulnerabilities: List['Vulnerability'] = field(default_factory=list)
    score: int = 100
    started_at: datetime = None
    finished_at: datetime = None
    
    def start(self):
        """Inicia o scan (transição PENDING -> RUNNING)."""
        if self.status != ScanStatus.PENDING:
            raise InvalidScanStateError(
                current_state=self.status.value,
                operation="start"
            )
        
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.now()
    
    def add_vulnerability(self, vulnerability: 'Vulnerability'):
        """Adiciona uma vulnerabilidade ao scan."""
        # Não permite adicionar em scan finalizado (imutável)
        if self.status == ScanStatus.COMPLETED:
            raise InvalidScanStateError(
                current_state=self.status.value,
                operation="add_vulnerability"
            )
        
        if self.status == ScanStatus.FAILED:
            raise InvalidScanStateError(
                current_state=self.status.value,
                operation="add_vulnerability"
            )
        
        self.vulnerabilities.append(vulnerability)
    
    def finalize(self):
        """Finaliza o scan (transição RUNNING -> COMPLETED)."""
        if self.status != ScanStatus.RUNNING:
            raise InvalidScanStateError(
                current_state=self.status.value,
                operation="finalize"
            )
        
        self.finished_at = datetime.now()
        self.score = self._calculate_score()
        self.status = ScanStatus.COMPLETED
    
    def fail(self, reason: str = "Erro durante execução"):
        """Marca o scan como falho."""
        if self.status == ScanStatus.COMPLETED:
            raise InvalidScanStateError(
                current_state=self.status.value,
                operation="fail"
            )
        
        self.status = ScanStatus.FAILED
        self.finished_at = datetime.now()
    
    def _calculate_score(self) -> int:
        """Calcula o score final baseado nas vulnerabilidades encontradas."""
        initial_score = 100
        total_penalty = 0
        
        for vuln in self.vulnerabilities:
            total_penalty += vuln.get_severity_weight()
        
        final_score = initial_score + total_penalty  # weights são negativos
        
        # Score mínimo é 0
        return max(0, final_score)
    
    def get_risk_level(self) -> str:
        """Retorna o nível de risco baseado no score."""
        if self.score >= 90:
            return "A"
        elif self.score >= 75:
            return "B"
        elif self.score >= 50:
            return "C"
        else:
            return "D"
    
    def get_vulnerabilities_by_severity(self, severity: Severity) -> List['Vulnerability']:
        """Retorna lista de vulnerabilidades de uma severidade específica."""
        return [v for v in self.vulnerabilities if v.severity == severity]
    
    def count_by_severity(self) -> dict:
        """Retorna contagem de vulnerabilidades por severidade."""
        counts = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 0,
            Severity.MEDIUM: 0,
            Severity.LOW: 0,
        }
        
        for vuln in self.vulnerabilities:
            counts[vuln.severity] += 1
        
        return counts
    
    def get_duration(self) -> float:
        """Retorna a duração do scan em segundos."""
        if self.started_at is None:
            return 0.0
        
        end_time = self.finished_at if self.finished_at else datetime.now()
        duration = (end_time - self.started_at).total_seconds()
        return duration
    
    def has_critical_vulnerabilities(self) -> bool:
        """Verifica se há vulnerabilidades críticas."""
        return any(v.severity == Severity.CRITICAL for v in self.vulnerabilities)
    
    def get_total_vulnerabilities(self) -> int:
        """Retorna o total de vulnerabilidades encontradas."""
        return len(self.vulnerabilities)
    
    def __str__(self) -> str:
        """Representação amigável do Scan."""
        return (f"Scan {self.id[:8]}... - {self.status.value} - "
                f"Score: {self.score} - Vulnerabilidades: {self.get_total_vulnerabilities()}")
    
    def __repr__(self) -> str:
        """Representação técnica do Scan."""
        return (f"Scan(id={self.id}, target={self.target}, status={self.status.value}, "
                f"vulns={self.get_total_vulnerabilities()}, score={self.score})")