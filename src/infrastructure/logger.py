"""Sistema de logging estruturado."""

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional


class ScanLogger:
    
    def __init__(
        self,
        name: str = "API_Scanner",
        log_file: Optional[str] = None,
        level: int = logging.INFO,
        enable_console: bool = True
    ):
        self.logger = logging.getLogger(name)
        self.logger.setLevel(level)
        
        self.logger.handlers.clear()
        
        formatter = logging.Formatter(
            fmt='%(asctime)s | %(levelname)-8s | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
        if enable_console:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(level)
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)
        
        if log_file:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            
            file_handler = logging.FileHandler(log_file, encoding='utf-8')
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)
    
    def debug(self, message: str):
        self.logger.debug(message)
    
    def info(self, message: str):
        self.logger.info(message)
    
    def warning(self, message: str):
        self.logger.warning(message)
    
    def error(self, message: str):
        self.logger.error(message)
    
    def critical(self, message: str):
        self.logger.critical(message)
    
    def log_scan_start(self, target_url: str, modules_count: int):
        self.info("=" * 80)
        self.info("INICIANDO SCAN")
        self.info("=" * 80)
        self.info(f"Target: {target_url}")
        self.info(f"Módulos ativos: {modules_count}")
        self.info(f"Data/Hora: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    def log_scan_complete(self, target_url: str, duration: float, vulns_count: int, score: int):
        self.info("=" * 80)
        self.info("SCAN FINALIZADO")
        self.info("=" * 80)
        self.info(f"Target: {target_url}")
        self.info(f"Duração: {duration:.2f}s")
        self.info(f"Vulnerabilidades encontradas: {vulns_count}")
        self.info(f"Score final: {score}/100")
    
    def log_scan_error(self, target_url: str, error: str):
        self.error("=" * 80)
        self.error("SCAN FALHOU")
        self.error("=" * 80)
        self.error(f"Target: {target_url}")
        self.error(f"Erro: {error}")
    
    def log_module_execution(self, module_name: str, vulns_found: int, duration: float):
        status = "FALHA" if vulns_found > 0 else "OK"
        self.info(
            f"Módulo {module_name}: {status} | "
            f"Vulnerabilidades: {vulns_found} | "
            f"Duração: {duration:.2f}s"
        )
    
    def log_module_error(self, module_name: str, error: str):
        self.error(f"Erro no módulo {module_name}: {error}")
    
    def log_module_timeout(self, module_name: str, timeout: int):
        self.warning(f"Módulo {module_name} excedeu timeout de {timeout}s")
    
    def log_vulnerability_found(self, vulnerability):
        """
        Loga detalhes completos de uma vulnerabilidade encontrada.
        Usa nível de log baseado na severidade.
        """
        severity_value = vulnerability.severity.value.upper()
        
        log_methods = {
            'critical': self.critical,
            'high': self.error,
            'medium': self.warning,
            'low': self.info
        }
        
        log_method = log_methods.get(vulnerability.severity.value, self.warning)
        
        log_method("=" * 80)
        log_method("[VULNERABILIDADE DETECTADA]")
        log_method(f"ID: {vulnerability.id}")
        log_method(f"Título: {vulnerability.title}")
        log_method(f"Severidade: {severity_value}")
        log_method(f"Módulo: {vulnerability.module_name}")
        
        if vulnerability.description:
            log_method(f"Descrição: {vulnerability.description}")
        
        if vulnerability.evidence:
            log_method(f"Evidência: {vulnerability.evidence}")
        
        if vulnerability.recommendation:
            log_method(f"Recomendação: {vulnerability.recommendation}")
        
        if vulnerability.reference:
            log_method(f"Referência: {vulnerability.reference}")
        
        log_method(f"Timestamp: {vulnerability.timestamp}")
        log_method("=" * 80)


def get_default_logger() -> ScanLogger:
    logs_dir = Path.cwd() / "logs"
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = logs_dir / f"scan_{timestamp}.log"
    
    return ScanLogger(
        name="API_Scanner",
        log_file=str(log_file),
        level=logging.INFO,
        enable_console=True
    )