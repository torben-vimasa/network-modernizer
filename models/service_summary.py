from dataclasses import dataclass, field


@dataclass
class ServiceSummary:

    service: str

    protocol: str | None = None

    direction: str | None = None

    rule_count: int = 0
    active_rule_count: int = 0

    total_hits: int = 0

    endpoints: list[str] = field(
        default_factory=list
    )

    contexts: list[str] = field(
        default_factory=list
    )

    match_tiers: list[str] = field(
        default_factory=list
    )

    actions: list[str] = field(
        default_factory=list
    )