from dataclasses import dataclass

from models.nat_result import NATResult
from models.packet import Packet
from models.security_result import SecurityResult


@dataclass
class FirewallTraversalResult:

    firewall: str | None = None
    context: str | None = None

    ingress_interface: str | None = None
    egress_interface: str | None = None

    source_before: str | None = None
    source_after: str | None = None

    destination_before: str | None = None
    destination_after: str | None = None

    next_hop: str | None = None
    route: str | None = None

    output_packet: Packet | None = None

    security: SecurityResult | None = None
    nat: NATResult | None = None

    permitted: bool = False

    reason: str | None = None