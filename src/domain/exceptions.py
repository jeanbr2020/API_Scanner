class DomainException(Exception):
    """Exceção base para todos os erros de domínio."""
    
    def __init__(self, message: str):
        self.message = message
        super().__init__(self.message)


class InvalidTargetError(DomainException):
    """Lançada quando a URL do target é inválida."""
    
    def __init__(self, url: str, reason: str):
        message = f"Target inválido '{url}': {reason}"
        super().__init__(message)
        self.url = url
        self.reason = reason


class PrivateIPNotAllowedError(DomainException):
    """Lançada quando tentativa de scan em IP privado/localhost."""
    
    def __init__(self, host: str):
        message = f"Scan em IP privado não permitido: {host}"
        super().__init__(message)
        self.host = host


class InvalidScanStateError(DomainException):
    """Lançada quando operação não permitida no estado atual do scan."""
    
    def __init__(self, current_state: str, operation: str):
        message = f"Não é possível '{operation}' no estado '{current_state}'"
        super().__init__(message)
        self.current_state = current_state
        self.operation = operation


class InvalidSeverityError(DomainException):
    """Lançada quando severidade é inválida ou None."""
    
    def __init__(self, severity_value):
        message = f"Severidade inválida: {severity_value}"
        super().__init__(message)
        self.severity_value = severity_value