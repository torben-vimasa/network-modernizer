from dataclasses import dataclass

from models.confidence import Confidence


@dataclass
class BGPExplanation:

    matched: bool

    reason: str

    prefix: str | None = None
    next_hop: str | None = None
    as_path: str | None = None
    local_pref: int | None = None
    med: int | None = None
    origin: str | None = None
    vrf: str | None = None

    confidence: Confidence | None = None