from dataclasses import dataclass

from models.route_entry import RouteEntry


@dataclass
class FirewallRouteResult:

    matched: bool

    route: RouteEntry | None = None

    next_hop: str | None = None
    egress_interface: str | None = None

    reason: str | None = None