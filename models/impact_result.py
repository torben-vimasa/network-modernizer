from dataclasses import dataclass, field


@dataclass
class ImpactResult:

    source: str
    destination: str

    protocol: str | None = None
    service: str | None = None

    path_resolved: bool = False
    destination_reached: bool = False
    inventory_boundary: bool = False

    selected_candidate: int | None = None
    primary_path_index: int | None = None
    candidate_path_count: int = 0

    #
    # Primary / selected path impact.
    #
    affected_devices: list[str] = field(
        default_factory=list
    )

    affected_firewalls: list[str] = field(
        default_factory=list
    )

    affected_routers: list[str] = field(
        default_factory=list
    )

    affected_vrfs: list[str] = field(
        default_factory=list
    )

    primary_routes: list[dict] = field(
        default_factory=list
    )

    #
    # All candidate paths / potential impact.
    #
    candidate_devices: list[str] = field(
        default_factory=list
    )

    candidate_firewalls: list[str] = field(
        default_factory=list
    )

    candidate_routers: list[str] = field(
        default_factory=list
    )

    candidate_vrfs: list[str] = field(
        default_factory=list
    )

    candidate_routes: list[dict] = field(
        default_factory=list
    )

    #
    # Security / confidence.
    #
    security_disposition: str | None = None
    security_classification: str | None = None
    security_confidence: str | None = None

    confidence: str | None = None
    reason: str | None = None