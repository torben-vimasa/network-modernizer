from dataclasses import dataclass


@dataclass
class BGPRoute:

    prefix: str

    next_hop: str | None = None

    as_path: str | None = None

    local_pref: int | None = None

    med: int | None = None

    origin: str | None = None

    source_router: str | None = None

    vrf: str | None = None

    raw: str | None = None