from enum import Enum

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def get_weight(self) -> int:
        weights = {
            Severity.LOW: -5,
            Severity.MEDIUM: -10,
            Severity.HIGH: -15,
            Severity.CRITICAL: -25,
        }

        return weights[self]
    
    def get_label(self) -> str:
        labels = {
            Severity.LOW: "Baixo",
            Severity.MEDIUM: "Médio",
            Severity.HIGH: "Alto",
            Severity.CRITICAL: "Crítico",
        }

        return labels[self]
    
class ScanStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"