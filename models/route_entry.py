from dataclasses import dataclass


@dataclass
class RouteEntry:

    router: str
    vrf: str
    prefix: str
    next_hop: str

    protocol: str | None = None

    exit_interface: str | None = None
    ingress_interface: str | None = None

    metric: int | None = None
    admin_distance: int | None = None