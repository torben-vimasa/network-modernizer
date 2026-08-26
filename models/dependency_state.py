from dataclasses import dataclass, field


@dataclass
class DependencyState:

    dependency_key: str
    dependency_name: str

    operational_state: str = "unknown"

    confidence: str = "low"
    reason: str = ""

    source: str = "interface-state"

    evidence: list[dict] = field(
        default_factory=list
    )