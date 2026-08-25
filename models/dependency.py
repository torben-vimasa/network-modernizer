from dataclasses import dataclass, field


@dataclass
class Dependency:

    key: str
    name: str

    domain: str = "unknown"
    confidence: str = "low"
    reason: str = ""

    services: list[str] = field(
        default_factory=list
    )

    contexts: list[str] = field(
        default_factory=list
    )

    endpoint_keys: list[str] = field(
        default_factory=list
    )

    aliases: list[str] = field(
        default_factory=list
    )

    resolved_hosts: list[str] = field(
        default_factory=list
    )

    resolved_networks: list[str] = field(
        default_factory=list
    )

    parent_groups: list[str] = field(
        default_factory=list
    )

    member_count: int = 0
    endpoint_count: int = 0

    rule_count: int = 0
    observed_rule_count: int = 0
    total_hits: int = 0