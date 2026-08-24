from dataclasses import dataclass, field


@dataclass
class ProposedChange:

    change_type: str

    device: str | None = None
    scope: str | None = None

    prefix: str | None = None

    current_next_hop: str | None = None
    proposed_next_hop: str | None = None

    current_interface: str | None = None
    proposed_interface: str | None = None

    description: str | None = None

    metadata: dict = field(
        default_factory=dict
    )