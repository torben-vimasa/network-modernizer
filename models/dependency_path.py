from dataclasses import dataclass, field


@dataclass
class DependencyPathStep:

    sequence: int

    stage: str

    # Device / routing context
    device_type: str | None = None
    device: str | None = None
    context: str | None = None
    vrf: str | None = None

    # Forwarding decision
    prefix: str | None = None
    protocol: str | None = None
    next_hop: str | None = None

    # Interface / subnet information
    interface: str | None = None
    egress_interface: str | None = None
    address: str | None = None
    subnet: str | None = None

    # Semantic classification, when the step represents
    # a deterministic egress/boundary classification.
    classification: str | None = None
    classification_value: str | None = None

    # Original normalized evidence from the engine.
    # Retained for provenance and future reporting/debugging.
    evidence: dict = field(
        default_factory=dict
    )


@dataclass
class DependencyPath:

    dependency_key: str
    dependency_name: str

    # Query/source side. May be a host or network.
    source: str | None = None

    # One path represents one analysed L3 target.
    target_type: str | None = None
    target: str | None = None

    direction: str | None = None

    steps: list[DependencyPathStep] = field(
        default_factory=list
    )

    # Deterministic normalized representation of the forwarding path.
    # Paths with the same signature can later be grouped in reports.
    signature: str | None = None

    confidence: str = "low"

    # Explicit termination information.
    #
    # Examples:
    #   reached
    #   semantic-egress
    #   input-boundary
    #   routing-loop
    #   unresolved
    #   not-applicable
    termination: str = "unresolved"

    termination_value: str | None = None
    termination_reason: str = ""

    loop_detected: bool = False
