from dataclasses import dataclass, field


@dataclass
class EndpointClassification:

    endpoint_key: str
    display_name: str

    domain: str = "unknown"
    confidence: str = "low"
    reason: str = "No classification evidence"

    direction: str | None = None
    endpoint_type: str | None = None

    contexts: list[str] = field(
        default_factory=list
    )

    services: list[str] = field(
        default_factory=list
    )

    aliases: list[str] = field(
        default_factory=list
    )

    parent_groups: list[str] = field(
        default_factory=list
    )

    member_count: int = 0
    rule_count: int = 0
    observed_rule_count: int = 0
    total_hits: int = 0