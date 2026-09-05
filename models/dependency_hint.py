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

    router: str | None = None

    vrf: str | None = None

    interface: str | None = None

    subnet: str | None = None

    evidence: list[dict] = field(default_factory=list)

    # Target-analysis coverage.
    #
    # These fields describe how much of the dependency's resolved
    # L3 target set was actually analysed by the engine.
    #
    # They are intentionally separate from confidence:
    # confidence describes the quality of the analysed evidence,
    # while coverage describes how much of the target set was analysed.
    target_count: int = 0

    attempted_target_count: int = 0

    evidence_target_count: int = 0

    coverage: str = "not-applicable"
