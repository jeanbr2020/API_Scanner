"""Infrastructure layer - Implementações técnicas."""

from .http_client import HttpClient
from .logger import ScanLogger, get_default_logger

__all__ = [
    "HttpClient",
    "ScanLogger",
    "get_default_logger",
]