from dataclasses import dataclass

from models.bgp_explanation import BGPExplanation
from models.bgp_route import BGPRoute


@dataclass
class BGPResult:

    matched: bool

    route: BGPRoute | None = None

    reason: str | None = None

    explanation: BGPExplanation | None = None