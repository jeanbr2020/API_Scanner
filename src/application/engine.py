"""Engine principal de orquestração de scans."""

import asyncio
from typing import List, Optional
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from src.domain import Target, Scan, ScanResult, Vulnerability, Severity
from .contracts import SecurityModuleProtocol, HttpClientProtocol
from .module_loader import ModuleLoader


class ScanEngine:
    
    def __init__(
        self,
        http_client: HttpClientProtocol,
        modules_dir: Optional[str] = None,
        global_timeout: int = 300,
        module_timeout: int = 30,
        max_workers: int = 5,
        logger = None
    ):
        self.http_client = http_client
        self.global_timeout = global_timeout
        self.module_timeout = module_timeout
        self.max_workers = max_workers
        self.logger = logger
        
        self.module_loader = ModuleLoader(modules_dir)
        self.modules: List[SecurityModuleProtocol] = []
    
    def load_modules(self) -> int:
        self.modules = self.module_loader.load_all()
        return len(self.modules)
    
    def execute_scan(self, target: Target) -> ScanResult:
        if not self.modules:
            self.load_modules()
        
        if not self.modules:
            raise RuntimeError("Nenhum módulo ativo encontrado")
        
        scan = Scan(target=target)
        scan.start()
        
        if self.logger:
            self.logger.log_scan_start(target.normalized_url, len(self.modules))
        
        print(f"\n🔍 Iniciando scan em {target.normalized_url}")
        print(f"📦 {len(self.modules)} módulos ativos")
        print(f"⏱️  Timeout global: {self.global_timeout}s\n")
        
        try:
            vulnerabilities = self._execute_modules_parallel(target)
            
            for vuln in vulnerabilities:
                scan.add_vulnerability(vuln)
                
                if self.logger:
                    self.logger.log_vulnerability_found(vuln)
            
            scan.finalize()
            
            print(f"\n✅ Scan finalizado!")
            print(f"⏱️  Duração: {scan.get_duration():.2f}s")
            print(f"🔍 Vulnerabilidades encontradas: {scan.get_total_vulnerabilities()}")
            
            if self.logger:
                self.logger.log_scan_complete(
                    target.normalized_url,
                    scan.get_duration(),
                    scan.get_total_vulnerabilities(),
                    scan.score
                )
            
        except Exception as e:
            print(f"\n❌ Erro durante scan: {e}")
            scan.fail(reason=str(e))
            
            if self.logger:
                self.logger.log_scan_error(target.normalized_url, str(e))
            
            raise
        
        return ScanResult.from_scan(scan)
    
    def _execute_modules_parallel(self, target: Target) -> List[Vulnerability]:
        all_vulnerabilities = []
        
        try:
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {
                    executor.submit(self._execute_single_module, module, target): module
                    for module in self.modules
                }
                
                for future in futures:
                    module = futures[future]
                    
                    try:
                        vulnerabilities = future.result(timeout=self.module_timeout)
                        all_vulnerabilities.extend(vulnerabilities)
                        
                        if vulnerabilities:
                            print(f"  🔴 {module.name}: {len(vulnerabilities)} vulnerabilidade(s)")
                        else:
                            print(f"  🟢 {module.name}: OK")
                    
                    except FuturesTimeoutError:
                        print(f"  ⏱️  {module.name}: TIMEOUT ({self.module_timeout}s)")
                        
                        if self.logger:
                            self.logger.log_module_timeout(module.name, self.module_timeout)
                        
                        timeout_vuln = Vulnerability(
                            id=f"{module.name.upper()}-TIMEOUT",
                            title=f"Módulo {module.name} excedeu timeout",
                            severity=Severity.LOW,
                            module_name=module.name,
                            description=f"Timeout de {self.module_timeout}s excedido"
                        )
                        all_vulnerabilities.append(timeout_vuln)
                    
                    except Exception as e:
                        print(f"  ❌ {module.name}: ERRO - {str(e)}")
                        
                        if self.logger:
                            self.logger.log_module_error(module.name, str(e))
                        
                        error_vuln = Vulnerability(
                            id=f"{module.name.upper()}-ERROR",
                            title=f"Erro ao executar {module.name}",
                            severity=Severity.LOW,
                            module_name=module.name,
                            description=f"Erro: {str(e)}"
                        )
                        all_vulnerabilities.append(error_vuln)
        
        except Exception as e:
            print(f"\n❌ Erro crítico na execução paralela: {e}")
            raise
        
        return all_vulnerabilities
    
    def _execute_single_module(
        self,
        module: SecurityModuleProtocol,
        target: Target
    ) -> List[Vulnerability]:
        
        try:
            return module.execute(target, self.http_client)
        
        except Exception as e:
            raise RuntimeError(f"Falha em {module.name}: {str(e)}") from e
    
    def get_loaded_modules_info(self) -> dict:
        return {
            "total": len(self.modules),
            "enabled": self.module_loader.get_enabled_count(),
            "disabled": self.module_loader.get_disabled_count(),
            "modules": [
                {
                    "name": m.name,
                    "description": m.description,
                    "category": m.category,
                    "priority": m.priority,
                    "enabled": m.enabled
                }
                for m in self.modules
            ]
        }