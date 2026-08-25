from dataclasses import dataclass, field


@dataclass
class NetworkMapResult:

    network: str

    #
    # Inventory / object model.
    #
    network_objects: list[dict] = field(
        default_factory=list
    )

    object_groups: list[dict] = field(
        default_factory=list
    )

    #
    # Routing / topology.
    #
    routes: list[dict] = field(
        default_factory=list
    )

    #
    # Security / communication.
    #
    outbound_rules: list[dict] = field(
        default_factory=list
    )

    inbound_rules: list[dict] = field(
        default_factory=list
    )

    #
    # Useful summaries.
    #
    contexts: list[str] = field(
        default_factory=list
    )

    outbound_destinations: list[str] = field(
        default_factory=list
    )

    inbound_sources: list[str] = field(
        default_factory=list
    )

    services: list[str] = field(
        default_factory=list
    )

    protocols: list[str] = field(
        default_factory=list
    )

    route_count: int = 0
    network_object_count: int = 0
    object_group_count: int = 0
    outbound_rule_count: int = 0
    inbound_rule_count: int = 0

    confidence: str = "high"

    reason: str | None = None