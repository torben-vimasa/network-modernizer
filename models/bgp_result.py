from dataclasses import dataclass

from models.bgp_route import BGPRoute


@dataclass
class BGPResult:

    matched: bool

    route: BGPRoute | None = None

    reason: str | None = None