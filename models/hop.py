from dataclasses import dataclass


@dataclass
class Hop:

    router: str

    vrf: str

    route: str

    next_hop: str