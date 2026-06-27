from dataclasses import dataclass


@dataclass
class RouteEntry:
    router: str
    vrf: str
    prefix: str
    next_hop: str
    protocol: str = "static"