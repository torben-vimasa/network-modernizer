from dataclasses import dataclass, field


@dataclass
class NetworkHop:

    hop_number: int

    hop_type: str

    device: str | None = None

    context: str | None = None
    vrf: str | None = None

    ingress_interface: str | None = None
    egress_interface: str | None = None

    ip: str | None = None
    subnet: str | None = None

    route: str | None = None
    next_hop: str | None = None

    reason: str | None = None

    details: dict = field(default_factory=dict)