from dataclasses import dataclass
from typing import Optional


@dataclass
class SecurityContext:
    source: str
    destination: str
    service: Optional[str] = None
    protocol: Optional[str] = None

    trace_status: Optional[str] = None

    ingress_device: Optional[str] = None
    ingress_interface: Optional[str] = None

    egress_device: Optional[str] = None
    egress_interface: Optional[str] = None
    next_hop: Optional[str] = None

    firewall_traversed: bool = False
    acl_permitted: Optional[bool] = None
    nat_evaluated: bool = False

    inventory_boundary: bool = False
    forwarding_complete: bool = False