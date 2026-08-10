from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SecurityAssessment:
    classification: str
    disposition: str
    confidence: str

    message: str

    device: Optional[str] = None
    interface: Optional[str] = None
    next_hop: Optional[str] = None

    evidence: list[str] = field(default_factory=list)