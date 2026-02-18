"""Carregador dinâmico de módulos de segurança."""

import os
import importlib.util
import inspect
from typing import List, Type
from pathlib import Path

from .contracts import SecurityModuleProtocol, ModuleMetadata


class ModuleLoader:
    """
    Carrega dinamicamente módulos de segurança da pasta /modules/.
    
    Funcionalidades:
    - Auto-discovery de módulos
    - Validação de implementação do Protocol
    - Filtragem por enabled=True
    - Ordenação por priority
    """
    
    def __init__(self, modules_dir: str = None):
        """
        Inicializa o loader.
        
        Args:
            modules_dir: Caminho da pasta de módulos (default: src/modules/)
        """
        if modules_dir is None:
            # Detecta automaticamente: src/modules/
            current_file = Path(__file__)  # .../application/module_loader.py
            src_dir = current_file.parent.parent  # .../src/
            modules_dir = src_dir / "modules"
        
        self.modules_dir = Path(modules_dir)
        self._loaded_modules: List[SecurityModuleProtocol] = []
        self._metadata: List[ModuleMetadata] = []
    
    def load_all(self) -> List[SecurityModuleProtocol]:
        """
        Carrega todos os módulos da pasta, filtra enabled e ordena por priority.
        
        Returns:
            Lista de instâncias de módulos prontas para execução
            
        Raises:
            FileNotFoundError: Se pasta /modules/ não existir
        """
        if not self.modules_dir.exists():
            raise FileNotFoundError(
                f"Pasta de módulos não encontrada: {self.modules_dir}"
            )
        
        # Descobre todos os arquivos .py
        module_files = list(self.modules_dir.glob("*_module.py"))
        
        if not module_files:
            print(f"⚠️  Nenhum módulo encontrado em {self.modules_dir}")
            return []
        
        # Carrega cada arquivo
        for file_path in module_files:
            self._load_module_from_file(file_path)
        
        # Filtra apenas enabled
        enabled_modules = [m for m in self._loaded_modules if m.enabled]
        
        # Ordena por priority (menor = primeiro)
        enabled_modules.sort(key=lambda m: m.priority)
        
        return enabled_modules
    
    def _load_module_from_file(self, file_path: Path):
        """
        Carrega um módulo de um arquivo específico.
        
        Args:
            file_path: Caminho do arquivo .py
        """
        module_name = file_path.stem  # ex: "headers_module"
        
        try:
            # Importa dinamicamente o arquivo
            spec = importlib.util.spec_from_file_location(module_name, file_path)
            if spec is None or spec.loader is None:
                print(f"⚠️  Não foi possível carregar {module_name}")
                return
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Procura por classes que implementam o Protocol
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Ignora classes importadas de outros módulos
                if obj.__module__ != module_name:
                    continue
                
                # Verifica se implementa o Protocol
                if self._implements_protocol(obj):
                    # Instancia o módulo
                    instance = obj()
                    
                    # Armazena
                    self._loaded_modules.append(instance)
                    
                    # Cria metadata
                    metadata = ModuleMetadata(
                        name=instance.name,
                        description=instance.description,
                        category=instance.category,
                        priority=instance.priority,
                        enabled=instance.enabled,
                        file_path=str(file_path)
                    )
                    self._metadata.append(metadata)
                    
                    status = "✓" if instance.enabled else "✗"
                    print(f"{status} Carregado: {instance.name} (Priority: {instance.priority})")
        
        except Exception as e:
            print(f"❌ Erro ao carregar {module_name}: {e}")
    
    def _implements_protocol(self, cls: Type) -> bool:
        """
        Verifica se uma classe implementa SecurityModuleProtocol.
        
        Args:
            cls: Classe a ser verificada
            
        Returns:
            True se implementa todos os atributos/métodos necessários
        """
        required_attrs = ['name', 'description', 'category', 'priority', 'enabled']
        required_methods = ['execute']
        
        # Verifica atributos
        for attr in required_attrs:
            if not hasattr(cls, attr):
                return False
        
        # Verifica métodos
        for method in required_methods:
            if not hasattr(cls, method) or not callable(getattr(cls, method)):
                return False
        
        return True
    
    def get_metadata(self) -> List[ModuleMetadata]:
        """Retorna metadados de todos os módulos carregados."""
        return self._metadata
    
    def get_enabled_count(self) -> int:
        """Retorna quantidade de módulos ativos."""
        return sum(1 for m in self._loaded_modules if m.enabled)
    
    def get_disabled_count(self) -> int:
        """Retorna quantidade de módulos desabilitados."""
        return sum(1 for m in self._loaded_modules if not m.enabled)