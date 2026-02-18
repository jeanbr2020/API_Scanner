from typing import Protocol, List, Optional
from src.domain import Target, Vulnerability


class HttpClientProtocol(Protocol):
    """
    Contrato para cliente HTTP.
    Permite injeção de dependência e facilita testes (mock).
    """
    
    def get(self, url: str, timeout: Optional[int] = None, **kwargs) -> 'HttpResponse':
        """
        Executa requisição GET.
        
        Args:
            url: URL completa
            timeout: Timeout em segundos (opcional)
            **kwargs: Parâmetros adicionais (headers, params, etc)
            
        Returns:
            Objeto de resposta HTTP
        """
        ...
    
    def post(self, url: str, timeout: Optional[int] = None, **kwargs) -> 'HttpResponse':
        """Executa requisição POST."""
        ...
    
    def head(self, url: str, timeout: Optional[int] = None, **kwargs) -> 'HttpResponse':
        """Executa requisição HEAD."""
        ...
    
    def options(self, url: str, timeout: Optional[int] = None, **kwargs) -> 'HttpResponse':
        """Executa requisição OPTIONS."""
        ...


class HttpResponse(Protocol):
    """
    Contrato para resposta HTTP.
    Abstração sobre requests.Response.
    """
    
    status_code: int
    headers: dict
    text: str
    content: bytes
    url: str
    
    def json(self) -> dict:
        """Retorna resposta como JSON."""
        ...


class SecurityModuleProtocol(Protocol):
    """
    Contrato que todos os módulos de segurança devem seguir.
    
    Atributos obrigatórios:
        name: Nome único do módulo (ex: "headers_module")
        description: Descrição do que o módulo testa
        category: Categoria (ex: "headers", "authentication", "injection")
        priority: Prioridade de execução (menor = executa primeiro)
        enabled: Se o módulo está ativo
    
    Método obrigatório:
        execute(): Executa o teste e retorna vulnerabilidades
    """
    
    # Metadados do módulo
    name: str
    description: str
    category: str
    priority: int  # Menor = maior prioridade (0 = primeiro)
    enabled: bool
    
    def execute(self, target: Target, http_client: HttpClientProtocol) -> List[Vulnerability]:
        """
        Executa o teste de segurança no target.
        
        Args:
            target: Alvo do scan (URL normalizada, host, etc)
            http_client: Cliente HTTP injetado pela Engine
            
        Returns:
            Lista de vulnerabilidades encontradas (pode ser vazia [])
            
        Raises:
            Exception: Qualquer exceção deve ser tratada pela Engine
        
        Exemplo de implementação:
            def execute(self, target, http_client):
                vulnerabilities = []
                
                try:
                    response = http_client.get(target.normalized_url)
                    
                    if 'X-Frame-Options' not in response.headers:
                        vulnerabilities.append(Vulnerability(
                            id="HEADERS-001",
                            title="Missing X-Frame-Options",
                            severity=Severity.MEDIUM,
                            module_name=self.name
                        ))
                        
                except Exception as e:
                    # Engine vai capturar e logar
                    raise
                
                return vulnerabilities
        """
        ...


class ModuleMetadata:
    """
    Metadados de um módulo carregado.
    Usado pelo ModuleLoader para tracking.
    """
    
    def __init__(
        self,
        name: str,
        description: str,
        category: str,
        priority: int,
        enabled: bool,
        file_path: str
    ):
        self.name = name
        self.description = description
        self.category = category
        self.priority = priority
        self.enabled = enabled
        self.file_path = file_path
    
    def __repr__(self) -> str:
        status = "✓" if self.enabled else "✗"
        return f"ModuleMetadata({status} {self.name} [P{self.priority}] - {self.category})"