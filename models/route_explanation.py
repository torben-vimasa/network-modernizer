from dataclasses import dataclass
from models.confidence import Confidence


@dataclass
class RouteExplanation:

    destination: str

    matched_prefix: str

    reason: str

    protocol: str

    next_hop: str

    confidence: Confidence