from dataclasses import dataclass, field


@dataclass
class DependencyHint:

    dependency_key: str
    dependency_name: str

    #
    # Semantic classification of the dependency/path.
    #
    hint_type: str = "unknown"
    hint_value: str | None = None

    confidence: str = "low"
    reason: str = ""

    source: str = "routing"

    #
    # Deterministic forwarding facts.
    #
    router: str | None = None
    vrf: str | None = None
    interface: str | None = None
    subnet: str | None = None

    evidence: list[dict] = field(
        default_factory=list
    )