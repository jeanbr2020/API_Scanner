import requests
from typing import Optional, Any
from requests.exceptions import RequestException, Timeout, ConnectionError


class HttpClient:
    
    def __init__(
        self,
        default_timeout: int = 10,
        verify_ssl: bool = True,
        max_retries: int = 2,
        user_agent: str = None
    ):
        self.default_timeout = default_timeout
        self.verify_ssl = verify_ssl
        self.max_retries = max_retries
        
        self.session = requests.Session()
        
        if user_agent:
            self.session.headers.update({'User-Agent': user_agent})
        else:
            self.session.headers.update({
                'User-Agent': 'API-Security-Scanner/1.0'
            })
        
        adapter = requests.adapters.HTTPAdapter(
            max_retries=max_retries,
            pool_connections=10,
            pool_maxsize=20
        )
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
    
    def get(self, url: str, timeout: Optional[int] = None, **kwargs) -> requests.Response:
        timeout = timeout or self.default_timeout
        
        try:
            response = self.session.get(
                url,
                timeout=timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            return response
        
        except Timeout:
            raise TimeoutError(f"Timeout ao acessar {url}")
        
        except ConnectionError as e:
            raise ConnectionError(f"Erro de conexão com {url}: {str(e)}")
        
        except RequestException as e:
            raise RuntimeError(f"Erro HTTP em {url}: {str(e)}")
    
    def post(self, url: str, timeout: Optional[int] = None, **kwargs) -> requests.Response:
        timeout = timeout or self.default_timeout
        
        try:
            response = self.session.post(
                url,
                timeout=timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            return response
        
        except Timeout:
            raise TimeoutError(f"Timeout ao acessar {url}")
        
        except ConnectionError as e:
            raise ConnectionError(f"Erro de conexão com {url}: {str(e)}")
        
        except RequestException as e:
            raise RuntimeError(f"Erro HTTP em {url}: {str(e)}")
    
    def head(self, url: str, timeout: Optional[int] = None, **kwargs) -> requests.Response:
        timeout = timeout or self.default_timeout
        
        try:
            response = self.session.head(
                url,
                timeout=timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            return response
        
        except Timeout:
            raise TimeoutError(f"Timeout ao acessar {url}")
        
        except ConnectionError as e:
            raise ConnectionError(f"Erro de conexão com {url}: {str(e)}")
        
        except RequestException as e:
            raise RuntimeError(f"Erro HTTP em {url}: {str(e)}")
    
    def options(self, url: str, timeout: Optional[int] = None, **kwargs) -> requests.Response:
        timeout = timeout or self.default_timeout
        
        try:
            response = self.session.options(
                url,
                timeout=timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            return response
        
        except Timeout:
            raise TimeoutError(f"Timeout ao acessar {url}")
        
        except ConnectionError as e:
            raise ConnectionError(f"Erro de conexão com {url}: {str(e)}")
        
        except RequestException as e:
            raise RuntimeError(f"Erro HTTP em {url}: {str(e)}")
    
    def close(self):
        self.session.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()