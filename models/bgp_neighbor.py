from dataclasses import dataclass


@dataclass
class BGPNeighbor:
    device: str
    local_as: int | None
    neighbor: str

    remote_as: int | None = None
    description: str | None = None

    activated: bool = False
    next_hop_self: bool = False

    prefix_list_in: str | None = None
    prefix_list_out: str | None = None

    route_map_in: str | None = None
    route_map_out: str | None = None