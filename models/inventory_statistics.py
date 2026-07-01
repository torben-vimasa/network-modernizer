from dataclasses import dataclass, field


@dataclass
class InventoryStatistics:

    firewalls: int = 0
    contexts: int = 0
    findings: int = 0

    critical: int = 0
    warnings: int = 0
    info: int = 0

    healthy_firewalls: int = 0

    health_score: int = 100
    health_explanation: list[str] = field(default_factory=list)