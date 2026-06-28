from dataclasses import dataclass


@dataclass
class RouteExplanation:

    destination: str

    matched_prefix: str

    reason: str

    protocol: str

    next_hop: str