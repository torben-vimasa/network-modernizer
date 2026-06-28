from dataclasses import dataclass

from models.confidence import Confidence


@dataclass
class NATExplanation:

    matched: bool

    reason: str

    source_before: str | None = None
    source_after: str | None = None

    destination_before: str | None = None
    destination_after: str | None = None

    rule_name: str | None = None
    direction: str | None = None
    section: str | None = None

    confidence: Confidence | None = None