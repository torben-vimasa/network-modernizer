from dataclasses import dataclass, field


@dataclass
class DependencyHint:

    dependency_key: str
    dependency_name: str

    hint_type: str = "unknown"
    hint_value: str | None = None

    confidence: str = "low"
    reason: str = ""

    source: str = "routing"

    evidence: list[dict] = field(
        default_factory=list
    )