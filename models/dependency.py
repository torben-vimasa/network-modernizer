from dataclasses import dataclass, field


@dataclass
class Dependency:

    key: str
    name: str

    domain: str = "unknown"
    confidence: str = "low"
    evidence_class: str = "unknown"
    observation_state: str = "unknown"
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

    endpoint_types: list[str] = field(
        default_factory=list
    )

    directions: list[str] = field(
        default_factory=list
    )

    match_tiers: list[str] = field(
        default_factory=list
    )

    tier_counters: dict[str, dict[str, int]] = field(
        default_factory=dict
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

    unresolved: list[str] = field(
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
    unknown_counter_count: int = 0
