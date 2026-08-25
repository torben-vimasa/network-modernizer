from dataclasses import dataclass, field


@dataclass
class LogicalEndpoint:

    key: str
    display_name: str

    endpoint_type: str | None = None
    direction: str | None = None

    aliases: list[str] = field(
        default_factory=list
    )

    raw_values: list[str] = field(
        default_factory=list
    )

    resolved_hosts: list[str] = field(
        default_factory=list
    )

    resolved_networks: list[str] = field(
        default_factory=list
    )

    resolved_objects: list[str] = field(
        default_factory=list
    )

    resolved_groups: list[str] = field(
        default_factory=list
    )

    unresolved: list[str] = field(
        default_factory=list
    )

    member_keys: list[str] = field(
        default_factory=list
    )

    member_count: int = 0

    parent_group_keys: list[str] = field(
        default_factory=list
    )

    parent_groups: list[str] = field(
        default_factory=list
    )

    services: list[str] = field(
        default_factory=list
    )

    contexts: list[str] = field(
        default_factory=list
    )

    match_tiers: list[str] = field(
        default_factory=list
    )

    rule_count: int = 0

    observed_rule_count: int = 0
    unknown_counter_count: int = 0

    total_hits: int = 0

    rules: list[dict] = field(
        default_factory=list
    )