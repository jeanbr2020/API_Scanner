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
        self.info(f"Iniciando scan em {target_url} com {modules_count} módulos")
    
    def log_scan_complete(self, target_url: str, duration: float, vulns_count: int, score: int):
        self.info(
            f"Scan completo em {target_url} | "
            f"Duração: {duration:.2f}s | "
            f"Vulnerabilidades: {vulns_count} | "
            f"Score: {score}"
        )
    
    def log_scan_error(self, target_url: str, error: str):
        self.error(f"Erro no scan de {target_url}: {error}")
    
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